//! Agent enrollment and administration API types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unauthenticated server information an agent reads before enrolling (`GET`).
pub const AGENT_INFO_PATH: &str = "/api/v1/agent/info";

/// Enrolls an agent with a single-use enrollment token (`POST`). Authenticated by the
/// token and a signature, not by a user session.
pub const AGENT_ENROLL_PATH: &str = "/api/v1/agent/enroll";

/// Agent protocol major versions this build supports.
pub const AGENT_PROTOCOL_VERSIONS: &[u32] = &[1];

/// Prefix of every enrollment token string.
pub const ENROLLMENT_TOKEN_PREFIX: &str = "vn_enroll_";

/// Domain separation prefix of the enrollment signature.
pub const ENROLLMENT_SIGNATURE_CONTEXT: &[u8] = b"vn-agent-enroll-v1";

/// Default lifetime of an enrollment token.
pub const DEFAULT_ENROLLMENT_TOKEN_MINUTES: u32 = 60;

/// Longest lifetime an enrollment token may have (24 hours).
pub const MAX_ENROLLMENT_TOKEN_MINUTES: u32 = 24 * 60;

/// The message an agent signs at enrollment with its Ed25519 key:
///
/// ```text
/// "vn-agent-enroll-v1" 0x00 installation_id token_id public_key
/// ```
///
/// The IDs are their 16 raw UUID bytes and the public key its 32 raw bytes, so every
/// field has a fixed length.
pub fn enrollment_signing_message(
    installation_id: Uuid,
    token_id: Uuid,
    public_key: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(ENROLLMENT_SIGNATURE_CONTEXT.len() + 1 + 16 + 16 + 32);
    message.extend_from_slice(ENROLLMENT_SIGNATURE_CONTEXT);
    message.push(0);
    message.extend_from_slice(installation_id.as_bytes());
    message.extend_from_slice(token_id.as_bytes());
    message.extend_from_slice(public_key);
    message
}

/// Kinds of agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// Runs in a Kubernetes cluster and reports its resources.
    Kubernetes,
}

impl AgentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            AgentKind::Kubernetes => "kubernetes",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "kubernetes" => Some(AgentKind::Kubernetes),
            _ => None,
        }
    }
}

/// Body of `GET /api/v1/agent/info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentServerInfo {
    /// Identifies this VN installation. Agents sign it at enrollment and store it.
    pub installation_id: Uuid,
    /// Agent protocol major versions the server supports.
    pub protocol_versions: Vec<u32>,
}

/// What an enrollment token enrolls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentTarget {
    /// Registers a new cluster with this display name.
    NewCluster { display_name: String },
    /// Replaces the agent of an existing source, for example after the agent was lost or
    /// revoked. The previous agent, if still active, is revoked at enrollment.
    ReplaceSource { source_id: Uuid },
}

/// Body of `POST /api/v1/projects/{slug}/enrollment-tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEnrollmentTokenRequest {
    pub kind: AgentKind,
    pub target: EnrollmentTarget,
    /// Lifetime in minutes. Defaults to [`DEFAULT_ENROLLMENT_TOKEN_MINUTES`], at most
    /// [`MAX_ENROLLMENT_TOKEN_MINUTES`].
    #[serde(default)]
    pub expires_in_minutes: Option<u32>,
}

/// Lifecycle state of an enrollment token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentTokenStatus {
    Active,
    Used,
    Expired,
    Revoked,
}

/// An enrollment token's metadata. The secret is never returned after creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kind: AgentKind,
    pub target: EnrollmentTarget,
    pub status: EnrollmentTokenStatus,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
}

/// Body of a successful `POST /api/v1/projects/{slug}/enrollment-tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedEnrollmentToken {
    pub token: EnrollmentToken,
    /// The token string to give the agent. Shown only in this response.
    pub secret: String,
    pub installation_id: Uuid,
}

/// Body of `GET /api/v1/projects/{slug}/enrollment-tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentTokenList {
    pub tokens: Vec<EnrollmentToken>,
}

/// Body of `POST /api/v1/agent/enroll`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    /// The enrollment token string.
    pub token: String,
    /// Installation ID from [`AgentServerInfo`], as signed.
    pub installation_id: Uuid,
    pub kind: AgentKind,
    /// Raw 32-byte Ed25519 public key, URL-safe base64 without padding.
    pub public_key: String,
    /// Ed25519 signature over [`enrollment_signing_message`], URL-safe base64 without
    /// padding.
    pub signature: String,
    pub agent_version: String,
    /// Agent protocol major versions the agent supports.
    pub protocol_versions: Vec<u32>,
    /// Cluster identity: the UID of the `kube-system` namespace.
    pub cluster_fingerprint: String,
}

/// Body of a successful `POST /api/v1/agent/enroll`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: Uuid,
    pub installation_id: Uuid,
    pub cluster_id: Uuid,
    pub source_id: Uuid,
    /// Identifies the registered public key: URL-safe base64 of its SHA-256.
    pub key_id: String,
}

/// Whether an agent may still connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Revoked,
}

/// Why an agent was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRevocationReason {
    /// A user revoked it.
    Revoked,
    /// A replacement agent enrolled for its source.
    Replaced,
}

impl AgentRevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            AgentRevocationReason::Revoked => "revoked",
            AgentRevocationReason::Replaced => "replaced",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "revoked" => Some(AgentRevocationReason::Revoked),
            "replaced" => Some(AgentRevocationReason::Replaced),
            _ => None,
        }
    }
}

/// An enrolled agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    pub id: Uuid,
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub project_id: Uuid,
    pub cluster_id: Uuid,
    pub cluster_name: String,
    pub source_id: Uuid,
    pub key_id: String,
    pub cluster_fingerprint: String,
    pub agent_version: String,
    pub protocol_versions: Vec<u32>,
    pub enrollment_token_id: Uuid,
    /// Creator of the enrollment token.
    pub enrolled_by: Option<Uuid>,
    pub enrolled_at: DateTime<Utc>,
    /// Client address of the enrollment request.
    pub source_address: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
    pub revocation_reason: Option<AgentRevocationReason>,
}

/// Body of `GET /api/v1/projects/{slug}/agents`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentList {
    pub agents: Vec<Agent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_message_layout() {
        let installation = Uuid::from_bytes([1; 16]);
        let token = Uuid::from_bytes([2; 16]);
        let message = enrollment_signing_message(installation, token, &[3; 32]);
        assert_eq!(message.len(), 18 + 1 + 16 + 16 + 32);
        assert!(message.starts_with(b"vn-agent-enroll-v1\0"));
        assert_eq!(&message[19..35], &[1; 16]);
        assert_eq!(&message[35..51], &[2; 16]);
        assert_eq!(&message[51..], &[3; 32]);
    }

    #[test]
    fn target_wire_format() {
        let target = EnrollmentTarget::NewCluster {
            display_name: "prod-east".into(),
        };
        assert_eq!(
            serde_json::to_string(&target).unwrap(),
            r#"{"type":"new_cluster","display_name":"prod-east"}"#
        );
        let replace: EnrollmentTarget = serde_json::from_str(
            r#"{"type":"replace_source","source_id":"00000000-0000-0000-0000-000000000001"}"#,
        )
        .unwrap();
        assert_eq!(
            replace,
            EnrollmentTarget::ReplaceSource {
                source_id: Uuid::from_u128(1)
            }
        );
        assert!(
            serde_json::from_str::<EnrollmentTarget>(
                r#"{"type":"new_cluster","display_name":"a","x":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn kind_and_reason_round_trip_through_the_database_names() {
        assert_eq!(
            AgentKind::from_db(AgentKind::Kubernetes.as_str()),
            Some(AgentKind::Kubernetes)
        );
        assert_eq!(AgentKind::from_db("docker"), None);
        for reason in [
            AgentRevocationReason::Revoked,
            AgentRevocationReason::Replaced,
        ] {
            assert_eq!(
                AgentRevocationReason::from_db(reason.as_str()),
                Some(reason)
            );
        }
    }

    #[test]
    fn enroll_request_rejects_unknown_fields() {
        let body = serde_json::json!({
            "token": "t",
            "installation_id": Uuid::nil(),
            "kind": "kubernetes",
            "public_key": "k",
            "signature": "s",
            "agent_version": "0.1.0",
            "protocol_versions": [1],
            "cluster_fingerprint": "f",
        });
        assert!(serde_json::from_value::<EnrollRequest>(body.clone()).is_ok());
        let mut extra = body;
        extra["private_key"] = "oops".into();
        assert!(serde_json::from_value::<EnrollRequest>(extra).is_err());
    }
}
