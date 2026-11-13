//! `POST /api/v1/agent/enroll`: an agent trades a single-use enrollment token for a
//! registered identity.
//!
//! The endpoint needs no user session. The caller proves it holds the token (its secret
//! hashes to the stored hash) and the private key for the public key it registers (an
//! Ed25519 signature over the token ID, public key, and installation ID). Until the token
//! is proven, every failure answers with the same generic error, so the response does not
//! reveal whether a token ID exists or why it was refused. The reason goes to the audit
//! log instead.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;
use vn_core::{
    AGENT_PROTOCOL_VERSIONS, AgentRevocationReason, EnrollRequest, EnrollResponse,
    enrollment_signing_message,
};

use super::{installation_id, notify_revoked, token};
use crate::audit::AuditEvent;
use crate::client_addr::ClientAddr;
use crate::error::{ApiFailure, ApiJson};
use crate::rate_limit::Acquire;
use crate::router::AppState;

const MAX_FINGERPRINT_LEN: usize = 255;
const MAX_AGENT_VERSION_LEN: usize = 64;
const MAX_PROTOCOL_VERSIONS: usize = 16;

/// A refused enrollment: what to answer, and what to audit.
struct Refusal {
    response: ApiFailure,
    /// Audit reason, or `None` for internal errors, which are logged instead.
    reason: Option<&'static str>,
    project_id: Option<Uuid>,
    token_id: Option<Uuid>,
}

impl Refusal {
    fn new(reason: &'static str, response: ApiFailure) -> Self {
        Self {
            response,
            reason: Some(reason),
            project_id: None,
            token_id: None,
        }
    }

    /// The generic answer for anything that fails before the token is proven.
    fn generic(reason: &'static str) -> Self {
        Self::new(
            reason,
            ApiFailure::new(
                StatusCode::UNAUTHORIZED,
                "enrollment_failed",
                "Enrollment failed: the token is invalid, expired, revoked, or already used, \
                 or the signature does not match.",
            ),
        )
    }

    fn invalid(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(reason, ApiFailure::invalid(message))
    }

    fn token(mut self, token_id: Uuid) -> Self {
        self.token_id = Some(token_id);
        self
    }

    fn project(mut self, project_id: Uuid) -> Self {
        self.project_id = Some(project_id);
        self
    }
}

impl From<sqlx::Error> for Refusal {
    fn from(err: sqlx::Error) -> Self {
        Self {
            response: err.into(),
            reason: None,
            project_id: None,
            token_id: None,
        }
    }
}

impl From<ApiFailure> for Refusal {
    fn from(response: ApiFailure) -> Self {
        Self {
            response,
            reason: None,
            project_id: None,
            token_id: None,
        }
    }
}

/// `POST /api/v1/agent/enroll` (unauthenticated; rate-limited per client address)
pub(crate) async fn enroll(
    State(state): State<AppState>,
    ClientAddr(client): ClientAddr,
    request: Request,
) -> Response {
    // Every attempt takes a token up front, so concurrent attempts cannot exceed the
    // limit. Successful enrollments hand it back: only failures count. The body is
    // read only after this check, so a limited client cannot make the server receive
    // or parse request bodies.
    if let Acquire::Limited { retry_after } = state.enroll_limiter.acquire(client) {
        tracing::debug!(client = ?client, "enrollment attempt rate-limited");
        let mut response = ApiFailure::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many failed enrollment attempts. Try again later.",
        )
        .into_response();
        let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
        return response;
    }

    // An admitted attempt keeps its limiter token while the body arrives, and a body
    // that stalls counts as a failed attempt.
    let body = tokio::time::timeout(
        state.enroll_body_timeout,
        ApiJson::<EnrollRequest>::from_request(request, &state),
    )
    .await;
    let result = match body {
        Ok(Ok(ApiJson(request))) => enroll_agent(&state, client, request).await,
        Ok(Err(rejection)) => Err(Refusal::new("invalid_request", rejection)),
        Err(_) => Err(Refusal::new(
            "body_timeout",
            ApiFailure::new(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "The request body did not arrive in time.",
            ),
        )),
    };
    match result {
        Ok(body) => {
            state.enroll_limiter.refund(client);
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(refusal) => {
            if let Some(reason) = refusal.reason {
                tracing::info!(client = ?client, reason, "agent enrollment refused");
                let event = AuditEvent::system("agent.enroll_failed").details(json!({
                    "reason": reason,
                    "token_id": refusal.token_id,
                    "source_address": client.map(|ip| ip.to_string()),
                }));
                let event = match refusal.project_id {
                    Some(project_id) => event.project(project_id),
                    None => event,
                };
                if let Err(err) = record_failure(&state, event).await {
                    tracing::error!(error = %err, "failed to audit a refused enrollment");
                }
            }
            refusal.response.into_response()
        }
    }
}

async fn record_failure(state: &AppState, event: AuditEvent) -> sqlx::Result<()> {
    let mut conn = state.db.acquire().await?;
    event.record(&mut conn).await
}

/// The enrolling token's scope, read while consuming it.
#[derive(sqlx::FromRow)]
struct ConsumedToken {
    project_id: Uuid,
    agent_kind: String,
    target_cluster_name: Option<String>,
    target_source_id: Option<Uuid>,
    created_by: Option<Uuid>,
}

/// A token row read to explain why consuming it failed.
#[derive(sqlx::FromRow)]
struct TokenState {
    project_id: Uuid,
    secret_matches: bool,
    used: bool,
    revoked: bool,
}

async fn enroll_agent(
    state: &AppState,
    client: Option<IpAddr>,
    request: EnrollRequest,
) -> Result<EnrollResponse, Refusal> {
    let installation_id = installation_id(&state.db).await?;
    if request.installation_id != installation_id {
        return Err(Refusal::new(
            "wrong_installation",
            ApiFailure::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "wrong_installation",
                "The installation ID does not match this server. Check the server URL the \
                 agent uses.",
            ),
        ));
    }
    if !request
        .protocol_versions
        .iter()
        .any(|v| AGENT_PROTOCOL_VERSIONS.contains(v))
    {
        return Err(Refusal::new(
            "unsupported_protocol",
            ApiFailure::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_protocol",
                format!(
                    "The agent supports none of the server's protocol versions {AGENT_PROTOCOL_VERSIONS:?}."
                ),
            ),
        ));
    }
    if request.protocol_versions.len() > MAX_PROTOCOL_VERSIONS {
        return Err(Refusal::invalid(
            "invalid_request",
            format!("`protocol_versions` may list at most {MAX_PROTOCOL_VERSIONS} versions."),
        ));
    }
    let protocol_versions = request
        .protocol_versions
        .iter()
        .map(|v| i32::try_from(*v))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Refusal::invalid("invalid_request", "`protocol_versions` is out of range."))?;
    if !is_printable(&request.cluster_fingerprint, MAX_FINGERPRINT_LEN) {
        return Err(Refusal::invalid(
            "invalid_request",
            format!(
                "`cluster_fingerprint` must be 1 to {MAX_FINGERPRINT_LEN} printable ASCII \
                 characters."
            ),
        ));
    }
    if !is_printable(&request.agent_version, MAX_AGENT_VERSION_LEN) {
        return Err(Refusal::invalid(
            "invalid_request",
            format!(
                "`agent_version` must be 1 to {MAX_AGENT_VERSION_LEN} printable ASCII \
                 characters."
            ),
        ));
    }
    let public_key: [u8; 32] = decode_fixed(&request.public_key).ok_or_else(|| {
        Refusal::invalid(
            "invalid_public_key",
            "`public_key` must be a 32-byte Ed25519 key in URL-safe base64 without padding.",
        )
    })?;
    let signature: [u8; 64] = decode_fixed(&request.signature).ok_or_else(|| {
        Refusal::invalid(
            "invalid_request",
            "`signature` must be a 64-byte Ed25519 signature in URL-safe base64 without \
             padding.",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .ok()
        .filter(|key| !key.is_weak())
        .ok_or_else(|| {
            Refusal::invalid(
                "invalid_public_key",
                "`public_key` is not a usable Ed25519 public key.",
            )
        })?;

    let Some(token) = token::parse(&request.token) else {
        return Err(Refusal::generic("malformed_token"));
    };
    let message = enrollment_signing_message(installation_id, token.id, &public_key);
    if verifying_key
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .is_err()
    {
        return Err(Refusal::generic("bad_signature").token(token.id));
    }

    let mut tx = state.db.begin().await?;
    // Consuming the token and creating the agent commit together. The conditional update
    // takes the token's row lock, so of several concurrent attempts exactly one finds the
    // token unused; the others wait for it and then match no row.
    let consumed: Option<ConsumedToken> = sqlx::query_as(
        "UPDATE enrollment_tokens SET used_at = now() \
         WHERE id = $1 AND secret_hash = $2 \
           AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now() \
         RETURNING project_id, agent_kind, target_cluster_name, target_source_id, created_by",
    )
    .bind(token.id)
    .bind(token.secret_hash())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(consumed) = consumed else {
        let refusal = explain_unusable_token(&mut tx, token.id, &token.secret_hash()).await;
        tx.rollback().await?;
        return Err(refusal);
    };
    let project_id = consumed.project_id;
    let refuse = |reason, response| {
        Refusal::new(reason, response)
            .token(token.id)
            .project(project_id)
    };

    // The caller has proven it holds the token, so specific errors are safe from here.
    if consumed.agent_kind != request.kind.as_str() {
        return Err(refuse(
            "kind_mismatch",
            ApiFailure::invalid(format!(
                "The enrollment token is for a `{}` agent.",
                consumed.agent_kind
            )),
        ));
    }
    let key_in_use: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agents WHERE public_key = $1)")
            .bind(public_key.as_slice())
            .fetch_one(&mut *tx)
            .await?;
    if key_in_use {
        return Err(refuse("public_key_reused", key_reused()));
    }

    let (cluster_id, source_id, replaced) = match (
        consumed.target_cluster_name.as_deref(),
        consumed.target_source_id,
    ) {
        (Some(display_name), None) => {
            let cluster_id: Uuid = sqlx::query_scalar(
                "INSERT INTO clusters (project_id, display_name, fingerprint) \
                 VALUES ($1, $2, $3) RETURNING id",
            )
            .bind(project_id)
            .bind(display_name)
            .bind(&request.cluster_fingerprint)
            .fetch_one(&mut *tx)
            .await?;
            let source_id: Uuid =
                sqlx::query_scalar("INSERT INTO sources (cluster_id) VALUES ($1) RETURNING id")
                    .bind(cluster_id)
                    .fetch_one(&mut *tx)
                    .await?;
            (cluster_id, source_id, None)
        }
        (None, Some(source_id)) => {
            // Locking the source serializes replacements of its agent.
            let target: Option<(Uuid, String)> = sqlx::query_as(
                "SELECT s.cluster_id, c.fingerprint FROM sources s \
                 JOIN clusters c ON c.id = s.cluster_id \
                 WHERE s.id = $1 AND c.project_id = $2 FOR NO KEY UPDATE OF s",
            )
            .bind(source_id)
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((cluster_id, fingerprint)) = target else {
                return Err(ApiFailure::internal(format!(
                    "enrollment token {} targets a missing source",
                    token.id
                ))
                .into());
            };
            if fingerprint != request.cluster_fingerprint {
                return Err(refuse(
                    "fingerprint_mismatch",
                    ApiFailure::new(
                        StatusCode::CONFLICT,
                        "fingerprint_mismatch",
                        "The cluster fingerprint differs from the one registered for this \
                         source. A replacement agent must run in the same cluster.",
                    ),
                ));
            }
            let replaced: Option<Uuid> = sqlx::query_scalar(
                "UPDATE agents SET revoked_at = now(), revocation_reason = $2 \
                 WHERE source_id = $1 AND revoked_at IS NULL RETURNING id",
            )
            .bind(source_id)
            .bind(AgentRevocationReason::Replaced.as_str())
            .fetch_optional(&mut *tx)
            .await?;
            (cluster_id, source_id, replaced)
        }
        _ => {
            return Err(ApiFailure::internal(format!(
                "enrollment token {} has an invalid target",
                token.id
            ))
            .into());
        }
    };

    let key_id = key_id(&public_key);
    let inserted: Result<(Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
        "INSERT INTO agents (kind, project_id, cluster_id, source_id, public_key, key_id, \
             cluster_fingerprint, agent_version, protocol_versions, enrollment_token_id, \
             enrolled_by, source_address) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet) \
         RETURNING id, enrolled_at",
    )
    .bind(request.kind.as_str())
    .bind(project_id)
    .bind(cluster_id)
    .bind(source_id)
    .bind(public_key.as_slice())
    .bind(&key_id)
    .bind(&request.cluster_fingerprint)
    .bind(&request.agent_version)
    .bind(&protocol_versions)
    .bind(token.id)
    .bind(consumed.created_by)
    .bind(client.map(|ip| ip.to_string()))
    .fetch_one(&mut *tx)
    .await;
    let (agent_id, enrolled_at) = match inserted {
        Ok(row) => row,
        // A concurrent enrollment registered the same key first.
        Err(sqlx::Error::Database(err))
            if err.is_unique_violation()
                && matches!(
                    err.constraint(),
                    Some("agents_public_key_key" | "agents_key_id_key")
                ) =>
        {
            return Err(refuse("public_key_reused", key_reused()));
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(previous) = replaced {
        AuditEvent::system("agent.revoke")
            .project(project_id)
            .agent(previous)
            .details(json!({
                "reason": AgentRevocationReason::Replaced,
                "replaced_by": agent_id,
                "token_id": token.id,
            }))
            .record(&mut tx)
            .await?;
        notify_revoked(&mut tx, previous).await?;
    }
    AuditEvent::system("agent.enroll")
        .project(project_id)
        .agent(agent_id)
        .details(json!({
            "token_id": token.id,
            "token_created_by": consumed.created_by,
            "cluster_id": cluster_id,
            "source_id": source_id,
            "key_id": key_id,
            "agent_version": request.agent_version,
            "source_address": client.map(|ip| ip.to_string()),
            "replaced_agent_id": replaced,
            "enrolled_at": enrolled_at,
        }))
        .record(&mut tx)
        .await?;
    tx.commit().await?;
    tracing::info!(%agent_id, %cluster_id, %source_id, "agent enrolled");

    Ok(EnrollResponse {
        agent_id,
        installation_id,
        cluster_id,
        source_id,
        key_id,
    })
}

fn key_reused() -> ApiFailure {
    ApiFailure::conflict(
        "This public key is already registered to an agent. Generate a new key pair for \
         each enrollment.",
    )
}

/// Works out, for the audit log, why a token could not be consumed. The caller always
/// gets the generic answer.
async fn explain_unusable_token(
    conn: &mut PgConnection,
    token_id: Uuid,
    secret_hash: &[u8],
) -> Refusal {
    let row: Result<Option<TokenState>, _> = sqlx::query_as(
        "SELECT project_id, secret_hash = $2 AS secret_matches, used_at IS NOT NULL AS used, \
                revoked_at IS NOT NULL AS revoked \
         FROM enrollment_tokens WHERE id = $1",
    )
    .bind(token_id)
    .bind(secret_hash)
    .fetch_optional(conn)
    .await;
    let row = match row {
        Ok(row) => row,
        Err(err) => return err.into(),
    };
    let Some(row) = row else {
        return Refusal::generic("unknown_token").token(token_id);
    };
    let reason = if !row.secret_matches {
        "wrong_secret"
    } else if row.revoked {
        "token_revoked"
    } else if row.used {
        "token_used"
    } else {
        "token_expired"
    };
    Refusal::generic(reason)
        .token(token_id)
        .project(row.project_id)
}

/// Key ID of an Ed25519 public key: URL-safe base64 of its SHA-256, without padding.
pub(crate) fn key_id(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() > N * 2 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}

fn is_printable(value: &str, max_len: usize) -> bool {
    (1..=max_len).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids_are_43_characters() {
        let id = key_id(&[7; 32]);
        assert_eq!(id.len(), 43);
        assert_eq!(id, key_id(&[7; 32]));
        assert_ne!(id, key_id(&[8; 32]));
    }

    #[test]
    fn decodes_only_exact_lengths() {
        let encoded = URL_SAFE_NO_PAD.encode([1u8; 32]);
        assert_eq!(decode_fixed::<32>(&encoded), Some([1; 32]));
        assert_eq!(decode_fixed::<64>(&encoded), None);
        assert_eq!(decode_fixed::<32>(&format!("{encoded}=")), None);
        assert_eq!(decode_fixed::<32>("not base64!"), None);
        assert_eq!(decode_fixed::<32>(&"A".repeat(1000)), None);
    }

    #[test]
    fn printable_values_have_bounded_length() {
        assert!(is_printable("v0.1.0+abc", 64));
        assert!(!is_printable("", 64));
        assert!(!is_printable("has space", 64));
        assert!(!is_printable("é", 64));
        assert!(!is_printable(&"a".repeat(65), 64));
    }
}
