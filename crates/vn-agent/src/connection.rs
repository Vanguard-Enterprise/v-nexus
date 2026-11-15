//! One WebSocket connection to the server, from the upgrade to the close.
//!
//! The connection reads `welcome`, sends `hello`, starts inventory collection (if the
//! agent has a collector) with a fresh [`SyncQueue`], answers server pings (tungstenite
//! does this while reading), and sends from the queue, numbering messages in queue
//! order, while fewer than `ack_window` messages are unacknowledged. It ends with an
//! [`Outcome`] that tells the [`Runner`](crate::runner::Runner) what to do next,
//! following the close code table in `docs/agent-protocol.md`. Collection stops with
//! the connection: unacknowledged observations are discarded, and the next connection
//! reconciles from new snapshots.

use std::collections::VecDeque;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as WsCloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message as WsMessage};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use vn_core::agent_protocol::{
    CloseCode, Envelope, ErrorMessage, Hello, Message, ServerMessage, Welcome, subprotocol,
};

use crate::client::ServerClient;
use crate::cluster::ClusterInfo;
use crate::collect::{Collect, Limits};
use crate::queue::{Outgoing, SyncQueue};

/// How long the upgrade and the `welcome` may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A connection open this long is healthy: the next reconnect starts the backoff over.
const HEALTHY_AFTER: Duration = Duration::from_secs(30);

/// Largest server message accepted. Server messages are small control messages.
const MAX_SERVER_MESSAGE: usize = 1024 * 1024;

/// How long to wait for the server to answer a close frame.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How a connection ended, and what to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Reconnect after a backoff. `healthy` connections start the backoff over.
    Reconnect { healthy: bool },
    /// The session token is no longer accepted: get a new session, then reconnect.
    SessionInvalid,
    /// The agent is revoked. Stop: it needs to be enrolled again.
    Revoked,
    /// The server rejected the agent's identity, such as its cluster fingerprint. Stop.
    IdentityMismatch(String),
    /// Shutdown was requested, and the connection is closed.
    Stopped,
}

/// What to do after the server closed the connection with `code`.
pub fn outcome_for_close(code: u16, reason: &str) -> Outcome {
    match CloseCode::from_code(code) {
        Some(CloseCode::ProtocolError) => {
            tracing::error!(
                code,
                reason,
                "the server closed the connection: protocol error"
            );
            Outcome::Reconnect { healthy: false }
        }
        Some(CloseCode::SessionInvalid) => {
            tracing::info!(
                code,
                reason,
                "the server ended the session; starting a new one"
            );
            Outcome::SessionInvalid
        }
        Some(CloseCode::Revoked) => Outcome::Revoked,
        Some(CloseCode::Superseded) => {
            tracing::warn!(
                code,
                reason,
                "a newer connection for this agent replaced this one; another agent \
                 process with the same identity may be running"
            );
            Outcome::Reconnect { healthy: false }
        }
        Some(CloseCode::IdentityMismatch) => Outcome::IdentityMismatch(reason.to_owned()),
        None => {
            tracing::info!(code, reason, "the server closed the connection");
            Outcome::Reconnect { healthy: false }
        }
    }
}

/// Opens a connection with session `token` and runs it until it ends or `shutdown`
/// becomes true.
pub async fn run(
    server: &ServerClient,
    token: &str,
    cluster: &ClusterInfo,
    collector: Option<&dyn Collect>,
    shutdown: &mut watch::Receiver<bool>,
) -> Outcome {
    let mut request = match server.connect_url().as_str().into_client_request() {
        Ok(request) => request,
        Err(err) => {
            tracing::error!(error = %err, "invalid connect URL");
            return Outcome::Reconnect { healthy: false };
        }
    };
    let headers = request.headers_mut();
    let protocol = subprotocol(1);
    match (format!("Bearer {token}").parse(), protocol.as_str().parse()) {
        (Ok(authorization), Ok(protocols)) => {
            headers.insert("authorization", authorization);
            headers.insert("sec-websocket-protocol", protocols);
        }
        _ => {
            tracing::error!("the session token is not a valid header value");
            return Outcome::SessionInvalid;
        }
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_SERVER_MESSAGE))
        .max_frame_size(Some(MAX_SERVER_MESSAGE));
    let connected = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(request, Some(config), true),
    )
    .await;
    let (ws, response) = match connected {
        Ok(Ok(connected)) => connected,
        Ok(Err(tungstenite::Error::Http(response))) => return refused(&response),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "failed to connect to the server");
            return Outcome::Reconnect { healthy: false };
        }
        Err(_) => {
            tracing::warn!("timed out connecting to the server");
            return Outcome::Reconnect { healthy: false };
        }
    };
    let selected = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok());
    let mut connection = Connection {
        ws,
        next_in: 1,
        next_out: 1,
        unacked: VecDeque::new(),
        window: 1,
        queue: SyncQueue::new(),
        last_traffic: Instant::now(),
    };
    if selected != Some(protocol.as_str()) {
        tracing::error!(
            selected = selected.unwrap_or("none"),
            "the server selected an unsupported subprotocol"
        );
        connection
            .close(CloseCode::ProtocolError.code(), "unsupported subprotocol")
            .await;
        return Outcome::Reconnect { healthy: false };
    }
    connection.serve(cluster, collector, shutdown).await
}

/// The outcome of an HTTP error answer to the upgrade request.
fn refused(response: &tungstenite::http::Response<Option<Vec<u8>>>) -> Outcome {
    let status = response.status();
    let error = response
        .body()
        .as_deref()
        .and_then(|body| serde_json::from_slice::<vn_core::ApiError>(body).ok());
    let code = error.as_ref().map_or("unknown", |e| e.error.as_str());
    let message = error.as_ref().map_or("", |e| e.message.as_str());
    match (status.as_u16(), code) {
        (401, _) => Outcome::SessionInvalid,
        (403, "agent_revoked") => Outcome::Revoked,
        _ => {
            tracing::warn!(%status, code, message, "the server refused the connection");
            Outcome::Reconnect { healthy: false }
        }
    }
}

struct Connection {
    ws: Ws,
    /// `seq` the next server message must have.
    next_in: u64,
    /// `seq` of the next agent message.
    next_out: u64,
    /// Sent inventory messages the server has not acknowledged yet, by `seq`. `hello`
    /// and `error` are outside the window: the server does not acknowledge them.
    unacked: VecDeque<u64>,
    /// Most unacknowledged inventory messages, from `welcome`.
    window: usize,
    /// Messages waiting for room in the window.
    queue: SyncQueue,
    last_traffic: Instant,
}

/// Why the serving loop stopped.
enum Ending {
    /// The server closed with this code and reason.
    ServerClosed(u16, String),
    /// The agent closes with this code and reason, then reconnects.
    AgentCloses(u16, &'static str),
    /// The socket failed.
    Lost,
    Shutdown,
}

impl Connection {
    async fn serve(
        &mut self,
        cluster: &ClusterInfo,
        collector: Option<&dyn Collect>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Outcome {
        let welcome = match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.read_welcome()).await {
            Ok(Ok(welcome)) => welcome,
            Ok(Err(ending)) => return self.finish(ending, false).await,
            Err(_) => {
                return self
                    .finish(
                        Ending::AgentCloses(CloseCode::ProtocolError.code(), "no welcome in time"),
                        false,
                    )
                    .await;
            }
        };
        let opened = Instant::now();
        tracing::info!(
            connection_id = %welcome.connection_id,
            sync_epoch = welcome.sync_epoch,
            "connected to the server"
        );
        // The server pings every heartbeat interval; three missed intervals mean the
        // connection is dead even if TCP has not noticed.
        let idle_timeout =
            Duration::from_secs(u64::from(welcome.heartbeat_interval_seconds.max(5)) * 3);

        self.window = usize::try_from(welcome.ack_window.max(1)).unwrap_or(usize::MAX);
        let hello = Hello {
            agent_version: crate::VERSION.to_owned(),
            capabilities: Vec::new(),
            cluster_fingerprint: cluster.fingerprint.clone(),
            kubernetes_version: cluster.kubernetes_version.clone(),
        };
        if let Err(ending) = self.send(&Outgoing::new(&hello)).await {
            return self.finish(ending, false).await;
        }
        // Dropped when the connection ends, which stops collection.
        let _collection = collector.map(|collector| {
            let limits = Limits {
                max_message_bytes: usize::try_from(welcome.max_message_bytes).unwrap_or(usize::MAX),
            };
            collector.start(self.queue.clone(), limits)
        });

        let queue = self.queue.clone();
        let ending = loop {
            let idle_deadline = self.last_traffic + idle_timeout;
            let room = self.in_flight() < self.window;
            let step: Result<(), Ending> = tokio::select! {
                frame = self.ws.next() => self.on_frame(frame).await,
                () = queue.changed(), if room => self.send_queued().await,
                () = tokio::time::sleep_until(idle_deadline) => Err(Ending::AgentCloses(
                    1000,
                    "no traffic from the server within the heartbeat timeout",
                )),
                changed = shutdown.changed() => match changed {
                    Ok(()) if !*shutdown.borrow() => Ok(()),
                    _ => Err(Ending::Shutdown),
                },
            };
            if let Err(ending) = step {
                break ending;
            }
        };
        let healthy = opened.elapsed() >= HEALTHY_AFTER;
        self.finish(ending, healthy).await
    }

    async fn read_welcome(&mut self) -> Result<Welcome, Ending> {
        loop {
            let frame = self.ws.next().await;
            let Some(text) = self.text(frame)? else {
                continue;
            };
            let message = self.parse(&text)?;
            return match message {
                (_, ServerMessage::Welcome(welcome)) => Ok(welcome),
                _ => Err(Ending::AgentCloses(
                    CloseCode::ProtocolError.code(),
                    "the first message must be `welcome`",
                )),
            };
        }
    }

    /// The text of a frame, `None` for control frames, or how the connection ends.
    fn text(
        &mut self,
        frame: Option<Result<WsMessage, tungstenite::Error>>,
    ) -> Result<Option<String>, Ending> {
        match frame {
            None => Err(Ending::Lost),
            Some(Err(err)) => {
                tracing::warn!(error = %err, "the connection failed");
                Err(Ending::Lost)
            }
            Some(Ok(WsMessage::Close(frame))) => {
                let (code, reason) = frame.map_or((1005, String::new()), |f| {
                    (u16::from(f.code), f.reason.to_string())
                });
                Err(Ending::ServerClosed(code, reason))
            }
            Some(Ok(message)) => {
                self.last_traffic = Instant::now();
                match message {
                    WsMessage::Text(text) => Ok(Some(text.to_string())),
                    WsMessage::Binary(_) => Err(Ending::AgentCloses(
                        CloseCode::ProtocolError.code(),
                        "binary frames are not used in protocol version 1",
                    )),
                    _ => Ok(None),
                }
            }
        }
    }

    /// Checks the envelope and its `seq`, and types the message.
    fn parse(&mut self, text: &str) -> Result<(u64, ServerMessage), Ending> {
        let protocol_error = |reason| Ending::AgentCloses(CloseCode::ProtocolError.code(), reason);
        let envelope =
            Envelope::parse(text).map_err(|_| protocol_error("a message is not an envelope"))?;
        if envelope.seq != self.next_in {
            tracing::error!(
                expected = self.next_in,
                got = envelope.seq,
                "server message out of sequence"
            );
            return Err(protocol_error("server message out of sequence"));
        }
        self.next_in += 1;
        let seq = envelope.seq;
        let kind = envelope.kind.clone();
        let message = ServerMessage::from_envelope(envelope).map_err(|err| {
            tracing::error!(kind, error = %err, "malformed server message");
            protocol_error("malformed server message")
        })?;
        Ok((seq, message))
    }

    async fn on_frame(
        &mut self,
        frame: Option<Result<WsMessage, tungstenite::Error>>,
    ) -> Result<(), Ending> {
        let Some(text) = self.text(frame)? else {
            return Ok(());
        };
        match self.parse(&text)? {
            (_, ServerMessage::Welcome(_)) => Err(Ending::AgentCloses(
                CloseCode::ProtocolError.code(),
                "`welcome` may be sent only once",
            )),
            (_, ServerMessage::Ack(ack)) => {
                tracing::trace!(seq = ack.seq, "acknowledged");
                if ack.seq >= self.next_out {
                    return Err(Ending::AgentCloses(
                        CloseCode::ProtocolError.code(),
                        "the server acknowledged a message that was not sent",
                    ));
                }
                while self.unacked.front().is_some_and(|seq| *seq <= ack.seq) {
                    self.unacked.pop_front();
                }
                self.send_queued().await
            }
            (seq, ServerMessage::Error(error)) => {
                tracing::warn!(
                    seq,
                    code = %error.code,
                    ref_seq = ?error.ref_seq,
                    message = error.message.as_deref().unwrap_or(""),
                    "the server reported an error"
                );
                Ok(())
            }
            (seq, ServerMessage::Unknown { kind }) => {
                tracing::debug!(seq, kind, "unsupported server message type");
                let error = Outgoing::new(&ErrorMessage::unsupported_type(&kind, seq));
                self.queue.update(|q| q.control(error));
                self.send_queued().await
            }
        }
    }

    /// Inventory messages sent and not yet acknowledged.
    fn in_flight(&self) -> usize {
        self.unacked.len()
    }

    /// Sends queued messages while the window has room.
    async fn send_queued(&mut self) -> Result<(), Ending> {
        while self.in_flight() < self.window {
            let Some(message) = self.queue.pop() else {
                break;
            };
            self.send(&message).await?;
        }
        Ok(())
    }

    async fn send(&mut self, message: &Outgoing) -> Result<(), Ending> {
        let text = message.frame(self.next_out);
        self.ws.send(WsMessage::text(text)).await.map_err(|err| {
            tracing::warn!(error = %err, "failed to send to the server");
            Ending::Lost
        })?;
        if !matches!(message.kind, Hello::TYPE | ErrorMessage::TYPE) {
            self.unacked.push_back(self.next_out);
        }
        self.next_out += 1;
        Ok(())
    }

    async fn finish(&mut self, ending: Ending, healthy: bool) -> Outcome {
        match ending {
            Ending::ServerClosed(code, reason) => {
                // Reading on flushes tungstenite's automatic reply to the close frame.
                self.drain().await;
                match outcome_for_close(code, &reason) {
                    Outcome::Reconnect { .. } => Outcome::Reconnect { healthy },
                    outcome => outcome,
                }
            }
            Ending::AgentCloses(code, reason) => {
                tracing::warn!(code, reason, "closing the connection");
                self.close(code, reason).await;
                Outcome::Reconnect { healthy: false }
            }
            Ending::Lost => Outcome::Reconnect { healthy },
            Ending::Shutdown => {
                self.close(1000, "agent stopping").await;
                Outcome::Stopped
            }
        }
    }

    async fn close(&mut self, code: u16, reason: &'static str) {
        let frame = CloseFrame {
            code: WsCloseCode::from(code),
            reason: reason.into(),
        };
        if self.ws.close(Some(frame)).await.is_ok() {
            self.drain().await;
        }
    }

    async fn drain(&mut self) {
        let drain = async { while let Some(Ok(_)) = self.ws.next().await {} };
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, drain).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_codes_map_to_the_protocol_actions() {
        assert_eq!(
            outcome_for_close(4000, ""),
            Outcome::Reconnect { healthy: false }
        );
        assert_eq!(outcome_for_close(4001, ""), Outcome::SessionInvalid);
        assert_eq!(outcome_for_close(4003, ""), Outcome::Revoked);
        assert_eq!(
            outcome_for_close(4009, ""),
            Outcome::Reconnect { healthy: false }
        );
        assert_eq!(
            outcome_for_close(4010, "fingerprint"),
            Outcome::IdentityMismatch("fingerprint".into())
        );
        assert_eq!(
            outcome_for_close(1001, "going away"),
            Outcome::Reconnect { healthy: false }
        );
    }
}
