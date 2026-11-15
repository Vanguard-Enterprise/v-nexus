//! Agent messages after `hello`: the extension point for inventory ingest and jobs.
//!
//! The connection checks the envelope and its `seq`, handles `hello`, and passes every
//! later message here, typed as an [`AgentMessage`]. A handler gets the
//! [`ConnectionContext`] (agent, source, and sync epoch) and an [`Outbound`] to answer on,
//! for example with `ack`. Returning a [`Close`] ends the connection with that code, for
//! example [`CloseCode::Revoked`] when an ingest transaction finds the agent revoked, or
//! [`CloseCode::Superseded`] when the epoch fence finds a newer connection.

use std::borrow::Cow;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use sqlx::PgPool;
use uuid::Uuid;
use vn_core::agent_protocol::{AgentMessage, CloseCode, Message, encode};

/// What a connection knows about its agent.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) connection_id: Uuid,
    pub(crate) agent_id: Uuid,
    pub(crate) project_id: Uuid,
    pub(crate) cluster_id: Uuid,
    pub(crate) source_id: Uuid,
    /// The source epoch allocated when this connection opened. Ingest persists nothing
    /// once the source's current epoch differs (the epoch fence).
    pub(crate) sync_epoch: i64,
    /// From `hello`. Decides whether resource versions may be compared (1.35 and later).
    pub(crate) kubernetes_version: Option<String>,
    pub(crate) db: PgPool,
}

/// How the connection should end: the close code it sends and records, and a reason for
/// the agent's logs. Reasons must not contain secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Close {
    pub(crate) code: u16,
    pub(crate) reason: Cow<'static, str>,
}

impl Close {
    pub(crate) fn new(code: CloseCode, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code: code.code(),
            reason: reason.into(),
        }
    }

    pub(crate) fn protocol(reason: impl Into<Cow<'static, str>>) -> Self {
        Self::new(CloseCode::ProtocolError, reason)
    }

    /// 1011: the server hit an unexpected error.
    pub(crate) fn internal() -> Self {
        Self {
            code: 1011,
            reason: "internal server error".into(),
        }
    }

    /// The socket failed, so nothing can be sent. Recorded as 1006 (abnormal closure).
    pub(crate) fn dropped() -> Self {
        Self {
            code: 1006,
            reason: "".into(),
        }
    }
}

impl From<sqlx::Error> for Close {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "agent connection database error");
        Self::internal()
    }
}

/// Sends server messages on a connection, numbering them.
pub(crate) struct Outbound<'a> {
    pub(crate) socket: &'a mut WebSocket,
    pub(crate) next_seq: &'a mut u64,
}

impl Outbound<'_> {
    /// Sends `body` and returns the `seq` it was sent with.
    pub(crate) async fn send<M: Message>(&mut self, body: &M) -> Result<u64, Close> {
        let seq = *self.next_seq;
        self.socket
            .send(WsMessage::text(encode(seq, body)))
            .await
            .map_err(|_| Close::dropped())?;
        *self.next_seq += 1;
        Ok(seq)
    }
}

/// The outcome of [`Dispatcher::dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dispatched {
    Handled,
    /// The connection answers `error { code: "unsupported_type", ref_seq }`.
    Unsupported,
}

/// Per-connection state for messages after `hello`. Ingest keeps its snapshot
/// bookkeeping here.
#[derive(Debug, Default)]
pub(crate) struct Dispatcher {}

impl Dispatcher {
    pub(crate) fn new(_ctx: &ConnectionContext) -> Self {
        Self {}
    }

    /// Handles message `seq`. Messages arrive in order, one at a time.
    pub(crate) async fn dispatch(
        &mut self,
        ctx: &ConnectionContext,
        seq: u64,
        message: AgentMessage,
        _out: &mut Outbound<'_>,
    ) -> Result<Dispatched, Close> {
        match message {
            AgentMessage::Hello(_) => Err(Close::protocol("`hello` may be sent only once")),
            AgentMessage::Error(error) => {
                tracing::warn!(
                    agent_id = %ctx.agent_id,
                    seq,
                    code = %error.code,
                    ref_seq = ?error.ref_seq,
                    message = error.message.as_deref().unwrap_or(""),
                    "agent reported an error"
                );
                Ok(Dispatched::Handled)
            }
            AgentMessage::Unknown { .. } => Ok(Dispatched::Unsupported),
        }
    }
}
