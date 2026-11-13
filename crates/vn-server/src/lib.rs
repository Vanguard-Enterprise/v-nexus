//! Vanguard Nexus server: HTTP API, static UI, and database lifecycle.

mod agents;
mod audit;
mod auth;
mod authz;
mod client_addr;
mod error;
mod health;
mod projects;
mod rate_limit;
mod router;

pub use auth::{AuthService, AuthSetupError};
pub use health::{DatabaseHealth, PingFuture};
pub use router::{AppState, router};

/// Migrations embedded from `crates/vn-server/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Version reported by the health endpoint.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
