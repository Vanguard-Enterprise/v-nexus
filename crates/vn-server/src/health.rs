use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};
use vn_core::{DatabaseStatus, HealthResponse, HealthStatus};

use crate::router::AppState;

/// Upper bound on the database check, so a stuck database cannot stall health probes.
pub(crate) const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Future returned by [`DatabaseHealth::ping`].
pub type PingFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'a>>;

/// Checks that the database answers queries. Implemented for [`PgPool`]; tests can supply
/// their own implementation to exercise the router without PostgreSQL.
pub trait DatabaseHealth: Send + Sync + 'static {
    fn ping(&self) -> PingFuture<'_>;
}

impl DatabaseHealth for PgPool {
    fn ping(&self) -> PingFuture<'_> {
        Box::pin(async move {
            let mut conn = DetachOnCancel(Some(self.acquire().await?));
            if let Some(conn) = conn.0.as_mut() {
                sqlx::query("SELECT 1").execute(&mut **conn).await?;
            }
            // The query finished, so the connection is in a known state: return it to the pool.
            drop(conn.0.take());
            Ok(())
        })
    }
}

/// Holds a pooled connection while a probe runs. If the probe is cancelled mid-query (for
/// example by [`PING_TIMEOUT`]), the connection is detached and dropped instead of being
/// returned to the pool. Returning it would make the pool validate it against a database
/// that is not answering, which can stall `PgPool::close` during shutdown.
struct DetachOnCancel(Option<PoolConnection<Postgres>>);

impl Drop for DetachOnCancel {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            drop(conn.detach());
        }
    }
}

pub(crate) async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let database = match tokio::time::timeout(PING_TIMEOUT, state.database.ping()).await {
        Ok(Ok(())) => DatabaseStatus::Ok,
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "database health check failed");
            DatabaseStatus::Unavailable
        }
        Err(_) => {
            tracing::warn!(timeout = ?PING_TIMEOUT, "database health check timed out");
            DatabaseStatus::Unavailable
        }
    };
    let (code, status) = match database {
        DatabaseStatus::Ok => (StatusCode::OK, HealthStatus::Ok),
        DatabaseStatus::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, HealthStatus::Degraded),
    };
    let body = HealthResponse {
        status,
        version: crate::VERSION.to_owned(),
        database,
    };
    (code, Json(body))
}
