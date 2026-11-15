//! One WebSocket connection to the server, from the upgrade to the close.
//!
//! The connection reads `welcome`, sends `hello`, answers server pings (tungstenite does
//! this while reading), and sends whatever is queued on its [`Outbound`] channel,
//! numbering messages in queue order. It ends with an [`Outcome`] that tells the
//! [`Runner`](crate::runner::Runner) what to do next, following the close code table in
//! `docs/agent-protocol.md`.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
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

/// How long the upgrade and the `welcome` may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A connection open this long is healthy: the next reconnect starts the backoff over.
const HEALTHY_AFTER: Duration = Duration::from_secs(30);

/// Largest server message accepted. Server messages are small control messages.
const MAX_SERVER_MESSAGE: usize = 1024 * 1024;

/// How long to wait for the server to answer a close frame.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Messages queued for sending, at most. Senders wait when it is full.
const QUEUE_CAPACITY: usize = 1024;

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

/// The connection was closed before the message could be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the connection is closed")]
pub struct ConnectionClosed;

struct Queued {
    kind: &'static str,
    body: Value,
}

/// Queues agent messages on one connection, which numbers them (`seq`) in queue order.
/// Collectors get a clone for each new connection. A connection's channel closes with
/// it: after a reconnect the agent reconciles from fresh snapshots instead of resending.
#[derive(Clone)]
pub struct Outbound {
    tx: mpsc::Sender<Queued>,
}

impl Outbound {
    fn channel() -> (Self, mpsc::Receiver<Queued>) {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        (Self { tx }, rx)
    }

    /// Queues `body`, waiting while the queue is full.
    pub async fn send<M: Message>(&self, body: &M) -> Result<(), ConnectionClosed> {
        let body = serde_json::to_value(body).expect("message bodies serialize to JSON");
        self.tx
            .send(Queued {
                kind: M::TYPE,
                body,
            })
            .await
            .map_err(|_| ConnectionClosed)
    }
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
    connection.serve(cluster, shutdown).await
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

        let (outbound, mut queue) = Outbound::channel();
        let hello = Hello {
            agent_version: crate::VERSION.to_owned(),
            capabilities: Vec::new(),
            cluster_fingerprint: cluster.fingerprint.clone(),
            kubernetes_version: cluster.kubernetes_version.clone(),
        };
        if outbound.send(&hello).await.is_err() {
            return self.finish(Ending::Lost, false).await;
        }

        let ending = loop {
            let idle_deadline = self.last_traffic + idle_timeout;
            let step: Result<(), Ending> = tokio::select! {
                frame = self.ws.next() => self.on_frame(frame).await,
                Some(queued) = queue.recv() => self.send(queued.kind, queued.body).await,
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
        drop(outbound);
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
                Ok(())
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
                let error = ErrorMessage::unsupported_type(&kind, seq);
                let body = serde_json::to_value(&error).expect("error bodies serialize");
                self.send(ErrorMessage::TYPE, body).await
            }
        }
    }

    async fn send(&mut self, kind: &'static str, body: Value) -> Result<(), Ending> {
        let envelope = Envelope {
            kind: kind.to_owned(),
            seq: self.next_out,
            body,
        };
        let text = serde_json::to_string(&envelope).expect("envelopes serialize to JSON");
        self.ws.send(WsMessage::text(text)).await.map_err(|err| {
            tracing::warn!(error = %err, "failed to send to the server");
            Ending::Lost
        })?;
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
