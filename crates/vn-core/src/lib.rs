//! Types shared by the Vanguard Nexus server, CLI, and agents.

pub mod agent_protocol;
pub mod agents;
pub mod api;

pub use agents::{
    AGENT_CHALLENGE_PATH, AGENT_CONNECT_PATH, AGENT_ENROLL_PATH, AGENT_INFO_PATH,
    AGENT_PROTOCOL_VERSIONS, AGENT_SESSION_MINUTES, AGENT_SESSION_PATH, AGENT_SESSION_TOKEN_PREFIX,
    Agent, AgentKind, AgentList, AgentRevocationReason, AgentServerInfo, AgentSession, AgentStatus,
    CHALLENGE_LIFETIME_SECONDS, Challenge, ChallengeRequest, CreateEnrollmentTokenRequest,
    CreatedEnrollmentToken, DEFAULT_ENROLLMENT_TOKEN_MINUTES, ENROLLMENT_SIGNATURE_CONTEXT,
    ENROLLMENT_TOKEN_PREFIX, EnrollRequest, EnrollResponse, EnrollmentTarget, EnrollmentToken,
    EnrollmentTokenList, EnrollmentTokenStatus, KEY_ID_LEN, MAX_ENROLLMENT_TOKEN_MINUTES,
    SESSION_SIGNATURE_CONTEXT, SessionRequest, enrollment_signing_message, session_signing_message,
};
pub use api::{
    API_PREFIX, API_VERSION, AUTH_CALLBACK_PATH, AUTH_LOGIN_PATH, AUTH_LOGOUT_PATH, AUTH_ME_PATH,
    ApiError, AssignRoleRequest, CreateProjectRequest, DatabaseStatus, HEALTH_PATH, HealthResponse,
    HealthStatus, InstallationRole, MeResponse, Project, ProjectList, ProjectMember,
    ProjectMemberList, ProjectPermissions, ProjectRole, User, UserList,
};
