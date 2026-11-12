//! Types shared by the Vanguard Nexus server, CLI, and agents.

pub mod api;

pub use api::{
    API_PREFIX, API_VERSION, AUTH_CALLBACK_PATH, AUTH_LOGIN_PATH, AUTH_LOGOUT_PATH, AUTH_ME_PATH,
    ApiError, AssignRoleRequest, CreateProjectRequest, DatabaseStatus, HEALTH_PATH, HealthResponse,
    HealthStatus, InstallationRole, MeResponse, Project, ProjectList, ProjectMember,
    ProjectMemberList, ProjectPermissions, ProjectRole, User, UserList,
};
