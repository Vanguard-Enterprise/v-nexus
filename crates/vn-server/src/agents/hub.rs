//! The agent connections open in this server process, and the background tasks that
//! keep them honest: the revocation listener and the cleanup of expired sessions and
//! consumed challenges.
//!
//! The hub is a process-local index from agent ID to its open connection. PostgreSQL
//! stays the source of truth: every connection rechecks its own row and its agent
//! periodically, so a missed notification or another server replica only delays a
//! close, it never keeps a revoked or superseded connection open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use uuid::Uuid;
use vn_core::agent_protocol::CloseCode;

use super::AGENT_REVOKED_CHANNEL;

/// How often expired sessions and consumed challenges are deleted.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Pause before reconnecting the revocation listener after an error.
const LISTENER_RETRY: Duration = Duration::from_secs(1);

/// An instruction to one open connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Control {
    /// Close with this code and reason.
    Close(CloseCode, &'static str),
    /// Recheck the agent and the connection row now, because a notification may have
    /// been missed.
    Recheck,
    /// The server is stopping: close with 1001 (going away).
    Shutdown,
}

struct Registered {
    connection_id: Uuid,
    sync_epoch: i64,
    control: mpsc::UnboundedSender<Control>,
}

/// Open agent connections by agent ID.
#[derive(Default)]
pub(crate) struct ConnectionHub {
    connections: Mutex<HashMap<Uuid, Registered>>,
    /// Signalled whenever a connection unregisters, for [`ConnectionHub::drain`].
    unregistered: Notify,
}

impl ConnectionHub {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Registered>> {
        self.connections.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a connection that is opening with `sync_epoch`. Of two connections for
    /// one agent, the one with the higher epoch is newer and stays; the other is told to
    /// close as superseded. Comparing epochs keeps the newer one even when the two
    /// register out of order.
    pub(crate) fn register(
        &self,
        agent_id: Uuid,
        connection_id: Uuid,
        sync_epoch: i64,
        control: mpsc::UnboundedSender<Control>,
    ) {
        let superseded = Control::Close(
            CloseCode::Superseded,
            "superseded by a newer connection for this agent",
        );
        let mut connections = self.lock();
        match connections.get(&agent_id) {
            Some(existing) if existing.sync_epoch > sync_epoch => {
                let _ = control.send(superseded);
            }
            _ => {
                let new = Registered {
                    connection_id,
                    sync_epoch,
                    control,
                };
                if let Some(old) = connections.insert(agent_id, new) {
                    let _ = old.control.send(superseded);
                }
            }
        }
    }

    /// Removes a connection that has ended, unless a newer one replaced it already.
    pub(crate) fn unregister(&self, agent_id: Uuid, connection_id: Uuid) {
        let mut connections = self.lock();
        if connections
            .get(&agent_id)
            .is_some_and(|c| c.connection_id == connection_id)
        {
            connections.remove(&agent_id);
        }
        drop(connections);
        self.unregistered.notify_waiters();
    }

    /// Tells the agent's open connection, if any, to close.
    pub(crate) fn close_agent(&self, agent_id: Uuid, code: CloseCode, reason: &'static str) {
        if let Some(connection) = self.lock().get(&agent_id) {
            let _ = connection.control.send(Control::Close(code, reason));
        }
    }

    fn broadcast(&self, control: &Control) {
        for connection in self.lock().values() {
            let _ = connection.control.send(control.clone());
        }
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    /// Tells every connection to close as the server stops, and waits up to `timeout`
    /// for them to record their closure.
    async fn drain(&self, timeout: Duration) {
        self.broadcast(&Control::Shutdown);
        let wait = async {
            loop {
                let unregistered = self.unregistered.notified();
                if self.len() == 0 {
                    return;
                }
                unregistered.await;
            }
        };
        if tokio::time::timeout(timeout, wait).await.is_err() {
            tracing::warn!(
                open = self.len(),
                "timed out waiting for agent connections to close"
            );
        }
    }
}

/// The running background tasks for agent connections. See
/// [`crate::AppState::start_agent_tasks`].
pub struct AgentTasks {
    hub: Arc<ConnectionHub>,
    tasks: Vec<JoinHandle<()>>,
}

impl AgentTasks {
    /// Closes open agent connections with 1001 (going away), waiting up to `timeout` for
    /// them to record it, then stops the background tasks. Call it before closing the
    /// database pool.
    pub async fn shutdown(self, timeout: Duration) {
        self.hub.drain(timeout).await;
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Closes connection rows left open by a server process that stopped without recording
/// them, then starts the revocation listener and the cleanup task. The first release
/// runs one server replica, so at startup no connection can be open.
pub(crate) async fn start(pool: &PgPool, hub: Arc<ConnectionHub>) -> sqlx::Result<AgentTasks> {
    let stale = sqlx::query(
        "UPDATE agent_connections SET closed_at = greatest(now(), last_seen_at) \
         WHERE closed_at IS NULL",
    )
    .execute(pool)
    .await?
    .rows_affected();
    if stale > 0 {
        tracing::info!(
            count = stale,
            "closed agent connections left open at startup"
        );
    }
    delete_expired(pool).await?;

    // Listen before returning, so a revocation committed after startup is never missed.
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(AGENT_REVOKED_CHANNEL).await?;
    let listen = tokio::spawn(listen_for_revocations(listener, pool.clone(), hub.clone()));
    let cleanup = tokio::spawn(clean_up(pool.clone()));
    Ok(AgentTasks {
        hub,
        tasks: vec![listen, cleanup],
    })
}

/// Closes the connection of every agent named in a revocation notification.
async fn listen_for_revocations(mut listener: PgListener, pool: PgPool, hub: Arc<ConnectionHub>) {
    loop {
        match listener.try_recv().await {
            Ok(Some(notification)) => match Uuid::try_parse(notification.payload()) {
                Ok(agent_id) => {
                    tracing::info!(%agent_id, "agent revoked; closing its connection");
                    hub.close_agent(agent_id, CloseCode::Revoked, "agent revoked");
                }
                Err(_) => tracing::warn!("ignoring a malformed agent revocation notification"),
            },
            // The listener lost its connection and has reconnected. Notifications sent
            // in between are lost, so every connection checks its agent now.
            Ok(None) => {
                tracing::warn!("revocation listener reconnected; rechecking agent connections");
                hub.broadcast(&Control::Recheck);
            }
            Err(sqlx::Error::PoolClosed) => return,
            Err(err) => {
                tracing::warn!(error = %err, "revocation listener failed; reconnecting");
                tokio::time::sleep(LISTENER_RETRY).await;
                match PgListener::connect_with(&pool).await {
                    Ok(mut fresh) => match fresh.listen(AGENT_REVOKED_CHANNEL).await {
                        Ok(()) => {
                            listener = fresh;
                            hub.broadcast(&Control::Recheck);
                        }
                        Err(err) => tracing::warn!(error = %err, "failed to listen again"),
                    },
                    Err(sqlx::Error::PoolClosed) => return,
                    Err(err) => tracing::warn!(error = %err, "failed to reconnect listener"),
                }
            }
        }
    }
}

async fn clean_up(pool: PgPool) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        interval.tick().await;
        match delete_expired(&pool).await {
            Ok(()) => {}
            Err(sqlx::Error::PoolClosed) => return,
            Err(err) => tracing::warn!(error = %err, "failed to delete expired agent sessions"),
        }
    }
}

/// Deletes expired agent sessions, and consumed challenges that can no longer be
/// answered anyway.
async fn delete_expired(pool: &PgPool) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM consumed_agent_challenges WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM agent_sessions WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> (
        mpsc::UnboundedSender<Control>,
        mpsc::UnboundedReceiver<Control>,
    ) {
        mpsc::unbounded_channel()
    }

    const SUPERSEDED: Control = Control::Close(
        CloseCode::Superseded,
        "superseded by a newer connection for this agent",
    );

    #[test]
    fn a_newer_connection_supersedes_the_older_one() {
        let hub = ConnectionHub::default();
        let agent = Uuid::from_u128(1);
        let (old_tx, mut old_rx) = channel();
        let (new_tx, mut new_rx) = channel();
        hub.register(agent, Uuid::from_u128(10), 1, old_tx);
        hub.register(agent, Uuid::from_u128(11), 2, new_tx);
        assert_eq!(old_rx.try_recv(), Ok(SUPERSEDED));
        assert!(new_rx.try_recv().is_err());

        // The old connection ending does not remove the new one.
        hub.unregister(agent, Uuid::from_u128(10));
        hub.close_agent(agent, CloseCode::Revoked, "agent revoked");
        assert_eq!(
            new_rx.try_recv(),
            Ok(Control::Close(CloseCode::Revoked, "agent revoked"))
        );
    }

    #[test]
    fn an_older_connection_registering_late_is_superseded_itself() {
        let hub = ConnectionHub::default();
        let agent = Uuid::from_u128(1);
        let (new_tx, mut new_rx) = channel();
        let (old_tx, mut old_rx) = channel();
        hub.register(agent, Uuid::from_u128(11), 2, new_tx);
        hub.register(agent, Uuid::from_u128(10), 1, old_tx);
        assert_eq!(old_rx.try_recv(), Ok(SUPERSEDED));
        assert!(new_rx.try_recv().is_err());
        assert_eq!(hub.len(), 1);
    }

    #[tokio::test]
    async fn drain_waits_for_connections_to_unregister() {
        let hub = Arc::new(ConnectionHub::default());
        let agent = Uuid::from_u128(1);
        let (tx, mut rx) = channel();
        hub.register(agent, Uuid::from_u128(10), 1, tx);
        let closer = {
            let hub = hub.clone();
            tokio::spawn(async move {
                assert_eq!(rx.recv().await, Some(Control::Shutdown));
                hub.unregister(agent, Uuid::from_u128(10));
            })
        };
        hub.drain(Duration::from_secs(5)).await;
        assert_eq!(hub.len(), 0);
        closer.await.unwrap();
    }
}
