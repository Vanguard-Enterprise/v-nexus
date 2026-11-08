//! Versioned HTTP API types.

use serde::{Deserialize, Serialize};

/// Current HTTP API version.
pub const API_VERSION: &str = "v1";

/// Path prefix for every route of the current API version.
pub const API_PREFIX: &str = "/api/v1";

/// Path of the health endpoint.
pub const HEALTH_PATH: &str = "/api/v1/health";

/// Body of `GET /api/v1/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    /// Version of the server build answering the request.
    pub version: String,
    pub database: DatabaseStatus,
}

/// Overall server health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
    Degraded,
}

/// Result of the server's database check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseStatus {
    Ok,
    Unavailable,
}

/// JSON body returned by API errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable, machine-readable error code such as `not_found`.
    pub error: String,
    /// Human-readable description.
    pub message: String,
}

impl ApiError {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_wire_format() {
        let body = HealthResponse {
            status: HealthStatus::Degraded,
            version: "1.2.3".into(),
            database: DatabaseStatus::Unavailable,
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"status":"degraded","version":"1.2.3","database":"unavailable"}"#
        );
    }
}
