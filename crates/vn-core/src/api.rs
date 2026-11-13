//! Versioned HTTP API types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Starts browser sign-in. Accepts an optional `return_to` query parameter holding a
/// same-origin path to open after sign-in.
pub const AUTH_LOGIN_PATH: &str = "/api/v1/auth/login";

/// Redirect URI the OIDC provider sends the browser back to.
pub const AUTH_CALLBACK_PATH: &str = "/api/v1/auth/callback";

/// Ends the current session (`POST`).
pub const AUTH_LOGOUT_PATH: &str = "/api/v1/auth/logout";

/// Describes the signed-in user (`GET`).
pub const AUTH_ME_PATH: &str = "/api/v1/auth/me";

/// A person known to VN through the configured identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    /// OIDC issuer that authenticated the user.
    pub issuer: String,
    /// Subject identifier assigned by the issuer.
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

/// Installation-wide roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationRole {
    /// Full access to every project and to installation settings.
    Admin,
}

/// Roles a user can hold in one project. `Operator` includes everything `Viewer` allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRole {
    Viewer,
    Operator,
}

impl ProjectRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProjectRole::Viewer => "viewer",
            ProjectRole::Operator => "operator",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "viewer" => Some(ProjectRole::Viewer),
            "operator" => Some(ProjectRole::Operator),
            _ => None,
        }
    }
}

/// Body of `GET /api/v1/auth/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeResponse {
    pub user: User,
    pub installation_roles: Vec<InstallationRole>,
    /// When the session ends at the latest, even if it stays active.
    pub session_expires_at: DateTime<Utc>,
}

/// A project as seen by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// The caller's role in the project. Installation admins may have none and still have
    /// full access.
    pub role: Option<ProjectRole>,
    /// What the caller may do in the project.
    pub permissions: ProjectPermissions,
}

/// The caller's effective permissions in a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectPermissions {
    pub view: bool,
    pub operate: bool,
    pub manage_members: bool,
}

/// Body of `GET /api/v1/projects`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectList {
    pub projects: Vec<Project>,
}

/// Body of `POST /api/v1/projects`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectRequest {
    /// URL-safe identifier: lowercase letters, digits, and inner hyphens, at most 63
    /// characters.
    pub slug: String,
    pub name: String,
}

/// Body of `PUT /api/v1/projects/{slug}/members/{user_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignRoleRequest {
    pub role: ProjectRole,
}

/// A user's role in a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMember {
    pub user: User,
    pub role: ProjectRole,
    pub granted_at: DateTime<Utc>,
}

/// Body of `GET /api/v1/projects/{slug}/members`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMemberList {
    pub members: Vec<ProjectMember>,
}

/// Body of `GET /api/v1/users`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserList {
    pub users: Vec<User>,
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

    #[test]
    fn project_role_wire_format() {
        assert_eq!(
            serde_json::to_string(&ProjectRole::Operator).unwrap(),
            r#""operator""#
        );
        for role in [ProjectRole::Viewer, ProjectRole::Operator] {
            assert_eq!(ProjectRole::from_db(role.as_str()), Some(role));
        }
        assert_eq!(ProjectRole::from_db("admin"), None);
        assert!(ProjectRole::Operator > ProjectRole::Viewer);
    }

    #[test]
    fn assign_role_rejects_unknown_roles_and_fields() {
        assert!(serde_json::from_str::<AssignRoleRequest>(r#"{"role":"admin"}"#).is_err());
        assert!(serde_json::from_str::<AssignRoleRequest>(r#"{"role":"viewer","x":1}"#).is_err());
    }
}
