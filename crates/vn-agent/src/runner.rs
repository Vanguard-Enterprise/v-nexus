//! The agent's main loop: get a session, connect, and reconnect with backoff, until the
//! agent is stopped, revoked, or rejected.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{TimeDelta, Utc};
use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::watch;
use vn_core::{AgentSession, SessionRequest, session_signing_message};

use crate::backoff::Backoff;
use crate::client::{CallError, ServerClient};
use crate::cluster::ClusterInfo;
use crate::collect::Collect;
use crate::connection::{self, Outcome};
use crate::identity::Identity;

/// A session is renewed this long before it expires, so it is not used at the edge.
const SESSION_MARGIN: TimeDelta = TimeDelta::seconds(60);

/// Why the agent stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// Shutdown was requested.
    Shutdown,
    /// The agent is revoked and needs to be enrolled again.
    Revoked,
    /// The server rejected the agent's identity, for example because it runs in a
    /// different cluster than it enrolled in.
    IdentityMismatch(String),
}

/// Connects an enrolled agent and keeps it connected.
pub struct Runner {
    server: ServerClient,
    identity: Identity,
    key: SigningKey,
    cluster: ClusterInfo,
    collector: Option<Box<dyn Collect>>,
    backoff: Backoff,
}

impl Runner {
    pub fn new(
        server: ServerClient,
        identity: Identity,
        cluster: ClusterInfo,
    ) -> anyhow::Result<Self> {
        let key = identity.signing_key()?;
        Ok(Self {
            server,
            identity,
            key,
            cluster,
            collector: None,
            backoff: Backoff::default(),
        })
    }

    /// Collects inventory with `collector` on every connection. Without one the agent
    /// only keeps its connection open.
    pub fn with_collector(mut self, collector: impl Collect + 'static) -> Self {
        self.collector = Some(Box::new(collector));
        self
    }

    /// Uses `backoff` instead of the default 1 to 60 seconds, so tests reconnect fast.
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Runs until shutdown (when `shutdown` becomes true), revocation, or an identity
    /// mismatch.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Stop {
        let mut session: Option<AgentSession> = None;
        loop {
            if *shutdown.borrow() {
                return Stop::Shutdown;
            }
            let usable = session
                .as_ref()
                .is_some_and(|s| s.expires_at - SESSION_MARGIN > Utc::now());
            if !usable {
                session = match self.new_session().await {
                    Ok(new) => Some(new),
                    Err(err) if err.code() == Some("agent_revoked") => return Stop::Revoked,
                    Err(err) => {
                        if err.code() == Some("session_failed") {
                            tracing::error!(
                                error = %err,
                                "the server does not accept this agent's identity; if the \
                                 server was reset or the agent was deleted, enroll it again"
                            );
                        } else {
                            tracing::warn!(error = %err, "failed to start a session");
                        }
                        if !self.pause(&mut shutdown).await {
                            return Stop::Shutdown;
                        }
                        continue;
                    }
                };
            }
            let token = session
                .as_ref()
                .map(|s| s.token.clone())
                .unwrap_or_default();
            let collector = self.collector.as_deref();
            match connection::run(
                &self.server,
                &token,
                &self.cluster,
                collector,
                &mut shutdown,
            )
            .await
            {
                Outcome::Reconnect { healthy } => {
                    if healthy {
                        self.backoff.reset();
                    }
                }
                Outcome::SessionInvalid => session = None,
                Outcome::Revoked => return Stop::Revoked,
                Outcome::IdentityMismatch(reason) => return Stop::IdentityMismatch(reason),
                Outcome::Stopped => return Stop::Shutdown,
            }
            if !self.pause(&mut shutdown).await {
                return Stop::Shutdown;
            }
        }
    }

    /// Waits for the next backoff delay. Returns false when shutdown was requested.
    async fn pause(&mut self, shutdown: &mut watch::Receiver<bool>) -> bool {
        let delay = self.backoff.next_delay();
        tracing::info!(delay = ?delay, "reconnecting after a delay");
        wait(delay, shutdown).await
    }

    /// Answers a fresh challenge with the agent's key.
    async fn new_session(&self) -> Result<AgentSession, CallError> {
        let challenge = self.server.challenge(self.identity.agent_id).await?;
        let nonce: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .ok()
            .and_then(|nonce| nonce.try_into().ok())
            .unwrap_or_default();
        let message = session_signing_message(
            self.identity.installation_id,
            self.identity.agent_id,
            &self.identity.key_id,
            challenge.challenge_id,
            &nonce,
        );
        let request = SessionRequest {
            agent_id: self.identity.agent_id,
            key_id: self.identity.key_id.clone(),
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
            expires_at: challenge.expires_at,
            mac: challenge.mac,
            signature: URL_SAFE_NO_PAD.encode(self.key.sign(&message).to_bytes()),
        };
        self.server.session(&request).await
    }
}

/// Sleeps for `delay`. Returns false early when shutdown is requested.
pub async fn wait(delay: std::time::Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    tokio::select! {
        () = tokio::time::sleep(delay) => true,
        _ = shutdown.wait_for(|stop| *stop) => false,
    }
}
