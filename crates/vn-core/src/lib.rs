//! Types shared by the Vanguard Nexus server, CLI, and agents.

pub mod api;

pub use api::{
    API_PREFIX, API_VERSION, ApiError, DatabaseStatus, HEALTH_PATH, HealthResponse, HealthStatus,
};
