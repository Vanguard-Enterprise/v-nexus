//! Types shared by the Vanguard Nexus server, CLI, and agents.

pub mod agents;
pub mod api;

pub use agents::{
    AGENT_ENROLL_PATH, AGENT_INFO_PATH, AGENT_PROTOCOL_VERSIONS, Agent, AgentKind, AgentList,
    AgentRevocationReason, AgentServerInfo, AgentStatus, CreateEnrollmentTokenRequest,
    CreatedEnrollmentToken, DEFAULT_ENROLLMENT_TOKEN_MINUTES, ENROLLMENT_SIGNATURE_CONTEXT,
    ENROLLMENT_TOKEN_PREFIX, EnrollRequest, EnrollResponse, EnrollmentTarget, EnrollmentToken,
    EnrollmentTokenList, EnrollmentTokenStatus, MAX_ENROLLMENT_TOKEN_MINUTES,
    enrollment_signing_message,
};
pub use api::{
    API_PREFIX, API_VERSION, AUTH_CALLBACK_PATH, AUTH_LOGIN_PATH, AUTH_LOGOUT_PATH, AUTH_ME_PATH,
    ApiError, AssignRoleRequest, CreateProjectRequest, DatabaseStatus, HEALTH_PATH, HealthResponse,
    HealthStatus, InstallationRole, MeResponse, Project, ProjectList, ProjectMember,
    ProjectMemberList, ProjectPermissions, ProjectRole, User, UserList,
};
