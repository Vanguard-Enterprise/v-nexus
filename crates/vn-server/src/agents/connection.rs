//! `GET /api/v1/agent/connect`: the agent WebSocket connection.
//!
//! Before upgrading, the server checks the upgrade request, selects the subprotocol, and
//! authenticates the session token, answering failures with an HTTP status and a JSON
//! error. After upgrading it allocates a sync epoch and records the connection in one
//! transaction that also closes any older connection of the agent, sends `welcome`,
//! waits for `hello`, and then hands every message to the [`Dispatcher`], which batches
//! inventory messages and applies a batch when [`Dispatcher::flush_deadline`] passes.
//!
//! A connection closes when the agent is revoked (notification or periodic recheck),
//! when a newer connection supersedes it, on a protocol error, after
//! [`AgentConnectionSettings::idle_timeout`] without traffic, and when the server stops.

use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::Instrument;
use uuid::Uuid;
use vn_core::AGENT_PROTOCOL_VERSIONS;
use vn_core::agent_protocol::{
    AgentMessage, CloseCode, DEFAULT_MAX_MESSAGE_BYTES, Envelope, ErrorMessage, Hello, Welcome,
    parse_subprotocol, subprotocol,
};

use super::dispatch::{Close, ConnectionContext, Dispatched, Dispatcher, Outbound};
use super::enroll::is_printable;
use super::hub::Control;
use super::session::{agent_revoked, disabled, plausible_session_token, random_uuid, rate_limited};
use crate::audit::AuditEvent;
use crate::auth::hash_token;
use crate::client_addr::ClientAddr;
use crate::error::ApiFailure;
use crate::rate_limit::Acquire;
use crate::router::AppState;

/// Longest accepted agent and Kubernetes version strings and capability names.
const MAX_VERSION_LEN: usize = 64;
const MAX_CAPABILITIES: usize = 64;

/// Longest close reason a WebSocket close frame can carry, in bytes.
const MAX_CLOSE_REASON: usize = 123;

/// How long to wait for the peer to answer a close frame.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Timings and limits of agent connections. The defaults follow
/// `docs/agent-protocol.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentConnectionSettings {
    /// How often the server pings (default 15 seconds).
    pub heartbeat_interval: Duration,
    /// A connection without traffic for this long is closed (default 45 seconds).
    pub idle_timeout: Duration,
    /// How often each connection records its last-seen time and checks that its agent
    /// is still active and its row still open (default 30 seconds). This bounds how
    /// long a revoked agent stays connected when a notification is missed.
    pub recheck_interval: Duration,
    /// How long the agent has to send `hello` after `welcome` (default 30 seconds).
    pub hello_timeout: Duration,
    /// Largest accepted message, announced in `welcome` (default 1 MiB).
    pub max_message_bytes: u32,
    /// Most unacknowledged agent messages, announced in `welcome` (default 256).
    pub ack_window: u32,
}

impl Default for AgentConnectionSettings {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(45),
            recheck_interval: Duration::from_secs(30),
            hello_timeout: Duration::from_secs(30),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            ack_window: 256,
        }
    }
}

/// The agent a session token belongs to.
#[derive(Debug, Clone, sqlx::FromRow)]
struct AuthorizedAgent {
    agent_id: Uuid,
    project_id: Uuid,
    cluster_id: Uuid,
    source_id: Uuid,
    cluster_fingerprint: String,
    agent_version: String,
    revoked: bool,
}

/// `GET /api/v1/agent/connect` (session token; failed attempts are rate-limited per
/// client address)
pub(crate) async fn connect(
    State(state): State<AppState>,
    ClientAddr(client): ClientAddr,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if state.challenge_key.is_none() {
        return disabled().into_response();
    }
    if let Acquire::Limited { retry_after } = state.connect_limiter.acquire(client) {
        tracing::debug!(client = ?client, "agent connection attempt rate-limited");
        return rate_limited(
            retry_after,
            "Too many failed connection attempts. Try again later.",
        );
    }
    let (upgrade, version, agent, token_hash) = match prepare(&state, &headers, upgrade).await {
        Ok(prepared) => prepared,
        Err(failure) => return failure.into_response(),
    };
    state.connect_limiter.refund(client);
    let settings = state.agent_settings;
    let limit = usize::try_from(settings.max_message_bytes).unwrap_or(usize::MAX);
    upgrade
        .protocols([subprotocol(version)])
        .max_message_size(limit)
        .max_frame_size(limit)
        .on_failed_upgrade(|err| tracing::warn!(error = %err, "agent WebSocket upgrade failed"))
        .on_upgrade(move |socket| run(socket, state, agent, token_hash))
}

/// Checks everything that can be answered with an HTTP error before upgrading.
async fn prepare(
    state: &AppState,
    headers: &HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<(WebSocketUpgrade, u32, AuthorizedAgent, Vec<u8>), ApiFailure> {
    let upgrade = upgrade.map_err(|rejection| {
        ApiFailure::new(
            rejection.status(),
            "websocket_required",
            format!(
                "This endpoint needs a WebSocket upgrade: {}",
                rejection.body_text()
            ),
        )
    })?;
    let version = select_version(headers).ok_or_else(|| {
        let offered: Vec<String> = AGENT_PROTOCOL_VERSIONS
            .iter()
            .map(|v| subprotocol(*v))
            .collect();
        ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "unsupported_protocol",
            format!(
                "No supported agent protocol version was offered in Sec-WebSocket-Protocol. \
                 The server supports: {}.",
                offered.join(", ")
            ),
        )
    })?;
    let session_invalid = || {
        ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "The session token is missing, invalid, or expired. Request a new challenge and \
             session.",
        )
    };
    let token = bearer_token(headers)
        .filter(|token| plausible_session_token(token))
        .ok_or_else(session_invalid)?;
    let token_hash = hash_token(token);
    let agent: Option<AuthorizedAgent> = sqlx::query_as(
        "SELECT a.id AS agent_id, a.project_id, a.cluster_id, a.source_id, \
                a.cluster_fingerprint, a.agent_version, a.revoked_at IS NOT NULL AS revoked \
         FROM agent_sessions s JOIN agents a ON a.id = s.agent_id \
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;
    let agent = agent.ok_or_else(session_invalid)?;
    if agent.revoked {
        return Err(agent_revoked());
    }
    Ok((upgrade, version, agent, token_hash))
}

/// The highest protocol version both sides support, from `Sec-WebSocket-Protocol`.
fn select_version(headers: &HeaderMap) -> Option<u32> {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| parse_subprotocol(name.trim()))
        .filter(|version| AGENT_PROTOCOL_VERSIONS.contains(version))
        .max()
}

/// The token of an `Authorization: Bearer <token>` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// How a connection ended.
enum Ending {
    /// The server closes with this code, or records 1006 when the socket failed.
    Server(Close),
    /// The agent closed, with this code if its close frame had one.
    Agent(Option<u16>),
}

struct Connection {
    socket: WebSocket,
    settings: AgentConnectionSettings,
    /// `seq` of the next server message.
    next_out: u64,
    /// `seq` the next agent message must have.
    next_in: u64,
    last_traffic: Instant,
    last_traffic_at: DateTime<Utc>,
}

async fn run(socket: WebSocket, state: AppState, agent: AuthorizedAgent, token_hash: Vec<u8>) {
    let connection_id = match random_uuid() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(error = %err, "failed to generate a connection ID");
            return;
        }
    };
    let span = tracing::info_span!(
        "agent_connection",
        %connection_id,
        agent_id = %agent.agent_id,
    );
    async move {
        let mut connection = Connection {
            socket,
            settings: state.agent_settings,
            next_out: 1,
            next_in: 1,
            last_traffic: Instant::now(),
            last_traffic_at: Utc::now(),
        };
        let (control_tx, mut control) = mpsc::unbounded_channel();
        let mut ctx = match open(&state, &agent, &token_hash, connection_id, control_tx).await {
            Ok(ctx) => ctx,
            Err(close) => {
                tracing::info!(code = close.code, reason = %close.reason, "agent connection refused");
                connection.end(Ending::Server(close)).await;
                return;
            }
        };
        tracing::debug!(
            project_id = %ctx.project_id,
            cluster_id = %ctx.cluster_id,
            source_id = %ctx.source_id,
            sync_epoch = ctx.sync_epoch,
            "agent connection opened"
        );
        let ending = connection.serve(&mut ctx, &agent, &mut control).await;
        let code = connection.end(ending).await;
        tracing::info!(code, "agent connection closed");
        let recorded = sqlx::query(
            "UPDATE agent_connections \
             SET closed_at = now(), close_code = $2, last_seen_at = greatest(last_seen_at, $3) \
             WHERE id = $1 AND closed_at IS NULL",
        )
        .bind(connection_id)
        .bind(i32::from(code))
        .bind(connection.last_traffic_at)
        .execute(&ctx.db)
        .await;
        if let Err(err) = recorded {
            tracing::error!(error = %err, "failed to record the closed agent connection");
        }
        state.agent_hub.unregister(ctx.agent_id, connection_id);
    }
    .instrument(span)
    .await;
}

/// Allocates the sync epoch and records the connection, superseding any older one, in
/// one transaction. The source row is locked before the agent row, in the same order as
/// replacement enrollment, so the two cannot deadlock.
async fn open(
    state: &AppState,
    agent: &AuthorizedAgent,
    token_hash: &[u8],
    connection_id: Uuid,
    control: mpsc::UnboundedSender<Control>,
) -> Result<ConnectionContext, Close> {
    let mut tx = state.db.begin().await?;
    let epoch: Option<i64> = sqlx::query_scalar(
        "UPDATE sources SET sync_epoch = sync_epoch + 1 WHERE id = $1 RETURNING sync_epoch",
    )
    .bind(agent.source_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(sync_epoch) = epoch else {
        return Err(Close::new(
            CloseCode::Revoked,
            "the agent's source no longer exists",
        ));
    };
    // The share lock orders this against a revocation, which updates the agent row.
    let current: Option<(bool, bool)> = sqlx::query_as(
        "SELECT a.revoked_at IS NOT NULL, \
                EXISTS (SELECT 1 FROM agent_sessions s \
                        WHERE s.token_hash = $2 AND s.agent_id = a.id AND s.expires_at > now()) \
         FROM agents a WHERE a.id = $1 FOR SHARE OF a",
    )
    .bind(agent.agent_id)
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    match current {
        None | Some((true, _)) => return Err(Close::new(CloseCode::Revoked, "agent revoked")),
        Some((false, false)) => {
            return Err(Close::new(
                CloseCode::SessionInvalid,
                "the session expired or was revoked",
            ));
        }
        Some((false, true)) => {}
    }
    sqlx::query(
        "UPDATE agent_connections SET closed_at = now(), close_code = $2 \
         WHERE agent_id = $1 AND closed_at IS NULL",
    )
    .bind(agent.agent_id)
    .bind(i32::from(CloseCode::Superseded.code()))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO agent_connections (id, agent_id, source_id, sync_epoch, agent_version) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(connection_id)
    .bind(agent.agent_id)
    .bind(agent.source_id)
    .bind(sync_epoch)
    .bind(&agent.agent_version)
    .execute(&mut *tx)
    .await?;
    // Registering before the commit means a revocation notification that arrives right
    // after it is not missed: it finds this connection in the hub.
    state
        .agent_hub
        .register(agent.agent_id, connection_id, sync_epoch, control);
    if let Err(err) = tx.commit().await {
        state.agent_hub.unregister(agent.agent_id, connection_id);
        return Err(err.into());
    }
    Ok(ConnectionContext {
        connection_id,
        agent_id: agent.agent_id,
        project_id: agent.project_id,
        cluster_id: agent.cluster_id,
        source_id: agent.source_id,
        sync_epoch,
        kubernetes_version: None,
        db: state.db.clone(),
    })
}

impl Connection {
    fn outbound(&mut self) -> Outbound<'_> {
        Outbound {
            socket: &mut self.socket,
            next_seq: &mut self.next_out,
        }
    }

    fn touch(&mut self) {
        self.last_traffic = Instant::now();
        self.last_traffic_at = Utc::now();
    }

    async fn serve(
        &mut self,
        ctx: &mut ConnectionContext,
        agent: &AuthorizedAgent,
        control: &mut mpsc::UnboundedReceiver<Control>,
    ) -> Ending {
        let settings = self.settings;
        let welcome = Welcome {
            connection_id: ctx.connection_id,
            sync_epoch: u64::try_from(ctx.sync_epoch).unwrap_or_default(),
            heartbeat_interval_seconds: whole_seconds(settings.heartbeat_interval),
            ack_window: settings.ack_window,
            max_message_bytes: settings.max_message_bytes,
            capabilities: Vec::new(),
        };
        if let Err(close) = self.outbound().send(&welcome).await {
            return Ending::Server(close);
        }

        let start = Instant::now();
        let mut ping = tokio::time::interval_at(
            start + settings.heartbeat_interval,
            settings.heartbeat_interval,
        );
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut recheck =
            tokio::time::interval_at(start + settings.recheck_interval, settings.recheck_interval);
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let hello_deadline = tokio::time::sleep(settings.hello_timeout);
        tokio::pin!(hello_deadline);
        let mut dispatcher: Option<Dispatcher> = None;

        loop {
            let idle_deadline = self.last_traffic + settings.idle_timeout;
            let flush_at = dispatcher.as_ref().and_then(Dispatcher::flush_deadline);
            let step: Result<(), Ending> = tokio::select! {
                control = control.recv() => match control {
                    Some(Control::Close(code, reason)) => {
                        Err(Ending::Server(Close::new(code, reason)))
                    }
                    Some(Control::Shutdown) => Err(Ending::Server(Close {
                        code: 1001,
                        reason: "server shutting down".into(),
                    })),
                    Some(Control::Recheck) => self.recheck(ctx).await.map_err(Ending::Server),
                    None => Err(Ending::Server(Close::internal())),
                },
                frame = self.socket.recv() => match frame {
                    None => Err(Ending::Server(Close::dropped())),
                    Some(Err(err)) => Err(Ending::Server(classify_error(err))),
                    Some(Ok(WsMessage::Close(frame))) => Err(Ending::Agent(frame.map(|f| f.code))),
                    Some(Ok(message)) => {
                        self.touch();
                        match message {
                            WsMessage::Text(text) => self
                                .on_text(ctx, agent, &mut dispatcher, text.as_str())
                                .await
                                .map_err(Ending::Server),
                            WsMessage::Binary(_) => Err(Ending::Server(Close::protocol(
                                "binary frames are not used in protocol version 1",
                            ))),
                            _ => Ok(()),
                        }
                    }
                },
                _ = ping.tick() => self
                    .socket
                    .send(WsMessage::Ping(Default::default()))
                    .await
                    .map_err(|_| Ending::Server(Close::dropped())),
                () = tokio::time::sleep_until(idle_deadline) => Err(Ending::Server(Close::protocol(
                    "no traffic within the heartbeat timeout",
                ))),
                _ = recheck.tick() => self.recheck(ctx).await.map_err(Ending::Server),
                () = &mut hello_deadline, if dispatcher.is_none() => Err(Ending::Server(
                    Close::protocol("no `hello` within the time limit"),
                )),
                () = tokio::time::sleep_until(flush_at.unwrap_or(idle_deadline)),
                    if flush_at.is_some() =>
                {
                    match dispatcher.as_mut() {
                        Some(dispatcher) => dispatcher
                            .flush(ctx, &mut self.outbound())
                            .await
                            .map_err(Ending::Server),
                        None => Ok(()),
                    }
                }
            };
            if let Err(ending) = step {
                return ending;
            }
        }
    }

    async fn on_text(
        &mut self,
        ctx: &mut ConnectionContext,
        agent: &AuthorizedAgent,
        dispatcher: &mut Option<Dispatcher>,
        text: &str,
    ) -> Result<(), Close> {
        let envelope =
            Envelope::parse(text).map_err(|_| Close::protocol("the message is not an envelope"))?;
        if envelope.seq != self.next_in {
            return Err(Close::protocol(format!(
                "expected seq {}, got {}",
                self.next_in, envelope.seq
            )));
        }
        self.next_in += 1;
        let seq = envelope.seq;
        let kind = envelope.kind.clone();
        let message = AgentMessage::from_envelope(envelope)
            .map_err(|_| Close::protocol(format!("malformed `{}` body", truncate(&kind, 32))))?;
        let Some(dispatcher) = dispatcher else {
            let AgentMessage::Hello(hello) = message else {
                return Err(Close::protocol("the first message must be `hello`"));
            };
            self.on_hello(ctx, agent, hello).await?;
            *dispatcher = Some(Dispatcher::new(ctx));
            return Ok(());
        };
        match dispatcher
            .dispatch(ctx, seq, message, &mut self.outbound())
            .await?
        {
            Dispatched::Handled => Ok(()),
            Dispatched::Unsupported => {
                tracing::debug!(seq, kind = %truncate(&kind, 64), "unsupported agent message type");
                self.outbound()
                    .send(&ErrorMessage::unsupported_type(truncate(&kind, 64), seq))
                    .await
                    .map(|_| ())
            }
        }
    }

    async fn on_hello(
        &mut self,
        ctx: &mut ConnectionContext,
        agent: &AuthorizedAgent,
        hello: Hello,
    ) -> Result<(), Close> {
        if !is_printable(&hello.agent_version, MAX_VERSION_LEN) {
            return Err(Close::protocol(
                "`agent_version` must be 1 to 64 printable ASCII characters",
            ));
        }
        if let Some(version) = &hello.kubernetes_version
            && !is_printable(version, MAX_VERSION_LEN)
        {
            return Err(Close::protocol(
                "`kubernetes_version` must be 1 to 64 printable ASCII characters",
            ));
        }
        if hello.capabilities.len() > MAX_CAPABILITIES
            || !hello
                .capabilities
                .iter()
                .all(|c| is_printable(c, MAX_VERSION_LEN))
        {
            return Err(Close::protocol(
                "`capabilities` must list at most 64 names of 1 to 64 printable ASCII characters",
            ));
        }
        if hello.cluster_fingerprint != agent.cluster_fingerprint {
            tracing::warn!("agent reported a different cluster fingerprint");
            let mut conn = ctx.db.acquire().await?;
            AuditEvent::system("agent.connect_refused")
                .project(ctx.project_id)
                .agent(ctx.agent_id)
                .details(json!({
                    "reason": "fingerprint_mismatch",
                    "connection_id": ctx.connection_id,
                }))
                .record(&mut conn)
                .await?;
            return Err(Close::new(
                CloseCode::IdentityMismatch,
                "the cluster fingerprint differs from the one registered at enrollment",
            ));
        }
        let mut tx = ctx.db.begin().await?;
        // The agent record shows the version the agent runs now. Its row is written before
        // the connection row, the same lock order as `open`, which locks the agent and
        // then closes its other connections; the opposite order could deadlock with a
        // replacement connection opening at the same time.
        sqlx::query("UPDATE agents SET agent_version = $2 WHERE id = $1 AND agent_version <> $2")
            .bind(ctx.agent_id)
            .bind(&hello.agent_version)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE agent_connections \
             SET agent_version = $2, kubernetes_version = $3, last_seen_at = $4 WHERE id = $1",
        )
        .bind(ctx.connection_id)
        .bind(&hello.agent_version)
        .bind(&hello.kubernetes_version)
        .bind(self.last_traffic_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        ctx.kubernetes_version = hello.kubernetes_version;
        tracing::info!(
            agent_version = %hello.agent_version,
            kubernetes_version = ctx.kubernetes_version.as_deref().unwrap_or("unknown"),
            sync_epoch = ctx.sync_epoch,
            "agent connected"
        );
        Ok(())
    }

    /// Records the last-seen time and checks that the agent is active and the
    /// connection row is still open. A database error leaves the connection open until
    /// the next check: ingest transactions check the agent themselves.
    async fn recheck(&mut self, ctx: &ConnectionContext) -> Result<(), Close> {
        let row: Result<Option<(bool, bool)>, _> = sqlx::query_as(
            "WITH touched AS ( \
                 UPDATE agent_connections SET last_seen_at = greatest(last_seen_at, $2) \
                 WHERE id = $1 AND closed_at IS NULL \
             ) \
             SELECT c.closed_at IS NOT NULL, a.revoked_at IS NOT NULL \
             FROM agent_connections c JOIN agents a ON a.id = c.agent_id WHERE c.id = $1",
        )
        .bind(ctx.connection_id)
        .bind(self.last_traffic_at)
        .fetch_optional(&ctx.db)
        .await;
        match row {
            Ok(None) | Ok(Some((_, true))) => Err(Close::new(CloseCode::Revoked, "agent revoked")),
            Ok(Some((true, false))) => Err(Close::new(
                CloseCode::Superseded,
                "the server closed this connection, superseded by a newer one",
            )),
            Ok(Some((false, false))) => Ok(()),
            Err(err) => {
                tracing::warn!(error = %err, "agent connection recheck failed");
                Ok(())
            }
        }
    }

    /// Ends the WebSocket: sends the server's close frame, or lets the agent's close
    /// complete. Returns the close code to record.
    async fn end(&mut self, ending: Ending) -> u16 {
        match ending {
            Ending::Server(close) => {
                if close.code != 1006 {
                    let frame = CloseFrame {
                        code: close.code,
                        reason: Utf8Bytes::from(truncate(&close.reason, MAX_CLOSE_REASON)),
                    };
                    if self
                        .socket
                        .send(WsMessage::Close(Some(frame)))
                        .await
                        .is_ok()
                    {
                        self.await_close().await;
                    }
                }
                close.code
            }
            Ending::Agent(code) => {
                // Reading again flushes the automatic reply to the agent's close frame.
                self.await_close().await;
                code.unwrap_or(1005)
            }
        }
    }

    async fn await_close(&mut self) {
        let drain = async {
            while let Some(Ok(message)) = self.socket.recv().await {
                if matches!(message, WsMessage::Close(_)) {
                    break;
                }
            }
        };
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, drain).await;
    }
}

/// 1009 (message too big) for a message over the size limit; otherwise the socket
/// failed.
fn classify_error(err: axum::Error) -> Close {
    match err.into_inner().downcast::<tungstenite::Error>() {
        Ok(err) if matches!(*err, tungstenite::Error::Capacity(_)) => Close {
            code: 1009,
            reason: "the message exceeds the size limit announced in `welcome`".into(),
        },
        _ => Close::dropped(),
    }
}

fn whole_seconds(duration: Duration) -> u32 {
    let seconds = duration.as_secs() + u64::from(duration.subsec_nanos() > 0);
    u32::try_from(seconds.max(1)).unwrap_or(u32::MAX)
}

/// `value` cut to at most `max` bytes at a character boundary.
fn truncate(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(name: header::HeaderName, values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn selects_the_highest_supported_version() {
        let select =
            |values: &[&str]| select_version(&headers(header::SEC_WEBSOCKET_PROTOCOL, values));
        assert_eq!(select(&["vn-agent.v1"]), Some(1));
        assert_eq!(select(&["vn-agent.v2, vn-agent.v1"]), Some(1));
        assert_eq!(select(&["chat", "vn-agent.v1"]), Some(1));
        assert_eq!(select(&["vn-agent.v2"]), None);
        assert_eq!(select(&["vn-agent.v01"]), None);
        assert_eq!(select(&[]), None);
    }

    #[test]
    fn reads_bearer_tokens() {
        let token = |value: &str| {
            bearer_token(&headers(header::AUTHORIZATION, &[value])).map(str::to_owned)
        };
        assert_eq!(token("Bearer abc").as_deref(), Some("abc"));
        assert_eq!(token("bearer abc").as_deref(), Some("abc"));
        assert_eq!(token("Basic abc"), None);
        assert_eq!(token("Bearer"), None);
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn truncates_at_character_boundaries() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("aé", 2), "a");
        assert_eq!(whole_seconds(Duration::from_millis(200)), 1);
        assert_eq!(whole_seconds(Duration::from_secs(15)), 15);
    }
}
