//! Agent sessions: `POST /api/v1/agent/auth/challenge` and `POST /api/v1/agent/auth/session`.
//!
//! A challenge is stateless. The server answers every challenge request, for unknown
//! agents too, and writes nothing: the MAC, keyed with the configured challenge key, lets
//! it recognize its own challenges when they come back. The session endpoint checks the
//! MAC and the expiry before it verifies the agent's Ed25519 signature, and enforces
//! single use only when it creates a session, by recording the challenge ID in the same
//! transaction. Session tokens are random, carry [`AGENT_SESSION_TOKEN_PREFIX`], and are
//! stored as SHA-256 hashes.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::Sha256;
use uuid::Uuid;
use vn_core::{
    AGENT_SESSION_MINUTES, AGENT_SESSION_TOKEN_PREFIX, AgentSession, CHALLENGE_LIFETIME_SECONDS,
    Challenge, ChallengeRequest, KEY_ID_LEN, SessionRequest, session_signing_message,
};

use super::installation_id;
use crate::audit::AuditEvent;
use crate::auth::{Token, hash_token};
use crate::client_addr::ClientAddr;
use crate::error::{ApiFailure, ApiJson};
use crate::rate_limit::{Acquire, RateLimiter};
use crate::router::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation prefix of the challenge MAC.
const CHALLENGE_MAC_CONTEXT: &[u8] = b"vn-agent-challenge-v1";

/// Length of a session token: the prefix and 32 random bytes in base64 without padding.
const SESSION_TOKEN_LEN: usize = AGENT_SESSION_TOKEN_PREFIX.len() + 43;

/// The key the challenge MAC is computed with. `Debug` redacts it.
pub(crate) struct ChallengeKey(vn_config::ChallengeKey);

impl ChallengeKey {
    pub(crate) fn new(key: vn_config::ChallengeKey) -> Self {
        Self(key)
    }

    fn mac(
        &self,
        agent_id: Uuid,
        challenge_id: Uuid,
        nonce: &[u8; 32],
        expires_at: i64,
    ) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(self.0.expose())
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(CHALLENGE_MAC_CONTEXT);
        mac.update(&[0]);
        mac.update(agent_id.as_bytes());
        mac.update(challenge_id.as_bytes());
        mac.update(nonce);
        mac.update(&expires_at.to_be_bytes());
        mac
    }
}

/// The answer when agent connections are not configured.
pub(crate) fn disabled() -> ApiFailure {
    ApiFailure::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "agents_disabled",
        "Agent connections are disabled: the server configuration has no \
         `agents.challenge_key_env`.",
    )
}

/// A 429 answer with `Retry-After`.
pub(crate) fn rate_limited(retry_after: std::time::Duration, message: &'static str) -> Response {
    let mut response =
        ApiFailure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", message).into_response();
    let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
    response
}

/// Reads a JSON body within the agent request body timeout.
async fn read_body<T: DeserializeOwned>(
    state: &AppState,
    request: Request,
) -> Result<T, ApiFailure> {
    match tokio::time::timeout(
        state.enroll_body_timeout,
        ApiJson::<T>::from_request(request, state),
    )
    .await
    {
        Ok(Ok(ApiJson(body))) => Ok(body),
        Ok(Err(rejection)) => Err(rejection),
        Err(_) => Err(ApiFailure::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "The request body did not arrive in time.",
        )),
    }
}

/// A random UUID (version 4) from the operating system's CSPRNG.
pub(crate) fn random_uuid() -> Result<Uuid, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

/// `POST /api/v1/agent/auth/challenge` (unauthenticated; rate-limited per client
/// address, every request counts)
pub(crate) async fn challenge(
    State(state): State<AppState>,
    ClientAddr(client): ClientAddr,
    request: Request,
) -> Response {
    let Some(key) = state.challenge_key.clone() else {
        return disabled().into_response();
    };
    if let Acquire::Limited { retry_after } = state.challenge_limiter.acquire(client) {
        tracing::debug!(client = ?client, "agent challenge rate-limited");
        return rate_limited(retry_after, "Too many challenge requests. Try again later.");
    }
    let request: ChallengeRequest = match read_body(&state, request).await {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let issued = (|| {
        let challenge_id = random_uuid()?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce)?;
        Ok::<_, getrandom::Error>((challenge_id, nonce))
    })();
    let (challenge_id, nonce) = match issued {
        Ok(issued) => issued,
        Err(err) => return ApiFailure::internal(err).into_response(),
    };
    let expires = Utc::now().timestamp() + CHALLENGE_LIFETIME_SECONDS;
    let Some(expires_at) = DateTime::from_timestamp(expires, 0) else {
        return ApiFailure::internal("challenge expiry out of range").into_response();
    };
    let mac = key
        .mac(request.agent_id, challenge_id, &nonce, expires)
        .finalize()
        .into_bytes();
    Json(Challenge {
        challenge_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at,
        mac: URL_SAFE_NO_PAD.encode(mac),
    })
    .into_response()
}

/// A refused session request: what to answer, and what to audit for a known agent.
struct Refusal {
    response: ApiFailure,
    /// Audit reason and the agent's project, for refusals about an existing agent.
    audit: Option<(&'static str, Uuid)>,
}

impl From<ApiFailure> for Refusal {
    fn from(response: ApiFailure) -> Self {
        Self {
            response,
            audit: None,
        }
    }
}

impl From<sqlx::Error> for Refusal {
    fn from(err: sqlx::Error) -> Self {
        ApiFailure::from(err).into()
    }
}

/// The answer for an unknown agent, a key that is not the agent's, and a bad signature
/// alike, so the response does not reveal which agents exist.
fn session_failed() -> ApiFailure {
    ApiFailure::new(
        StatusCode::UNAUTHORIZED,
        "session_failed",
        "Authentication failed: the agent is unknown, or the key or signature does not \
         match.",
    )
}

/// The answer to an agent that proved its identity but is revoked.
pub(crate) fn agent_revoked() -> ApiFailure {
    ApiFailure::new(
        StatusCode::FORBIDDEN,
        "agent_revoked",
        "The agent is revoked. Enroll it again with a new enrollment token.",
    )
}

#[derive(sqlx::FromRow)]
struct AgentKey {
    project_id: Uuid,
    public_key: Vec<u8>,
    key_id: String,
    revoked: bool,
}

/// `POST /api/v1/agent/auth/session` (unauthenticated; rate-limited per client address,
/// only failures count)
pub(crate) async fn session(
    State(state): State<AppState>,
    ClientAddr(client): ClientAddr,
    request: Request,
) -> Response {
    let Some(key) = state.challenge_key.clone() else {
        return disabled().into_response();
    };
    let limiter: &RateLimiter = &state.session_limiter;
    if let Acquire::Limited { retry_after } = limiter.acquire(client) {
        tracing::debug!(client = ?client, "agent session request rate-limited");
        return rate_limited(
            retry_after,
            "Too many failed session requests. Try again later.",
        );
    }
    let result = match read_body::<SessionRequest>(&state, request).await {
        Ok(request) => create_session(&state, &key, client, &request)
            .await
            .map_err(|refusal| (refusal, Some(request.agent_id))),
        Err(failure) => Err((failure.into(), None)),
    };
    match result {
        Ok(session) => {
            limiter.refund(client);
            (StatusCode::CREATED, Json(session)).into_response()
        }
        Err((refusal, agent_id)) => {
            if let (Some((reason, project_id)), Some(agent_id)) = (refusal.audit, agent_id) {
                tracing::info!(client = ?client, %agent_id, reason, "agent session refused");
                let event = AuditEvent::system("agent.session_failed")
                    .project(project_id)
                    .agent(agent_id)
                    .details(json!({
                        "reason": reason,
                        "source_address": client.map(|ip| ip.to_string()),
                    }));
                let recorded = async {
                    let mut conn = state.db.acquire().await?;
                    event.record(&mut conn).await
                };
                if let Err(err) = recorded.await {
                    tracing::error!(error = %err, "failed to audit a refused agent session");
                }
            }
            refusal.response.into_response()
        }
    }
}

async fn create_session(
    state: &AppState,
    key: &ChallengeKey,
    client: Option<IpAddr>,
    request: &SessionRequest,
) -> Result<AgentSession, Refusal> {
    let malformed = |field: &str| {
        ApiFailure::invalid(format!(
            "`{field}` is malformed. Send the challenge back unchanged."
        ))
    };
    let nonce: [u8; 32] = decode_fixed(&request.nonce).ok_or_else(|| malformed("nonce"))?;
    let mac: [u8; 32] = decode_fixed(&request.mac).ok_or_else(|| malformed("mac"))?;
    let signature: [u8; 64] = decode_fixed(&request.signature).ok_or_else(|| {
        ApiFailure::invalid(
            "`signature` must be a 64-byte Ed25519 signature in URL-safe base64 without \
             padding.",
        )
    })?;
    if request.key_id.len() != KEY_ID_LEN {
        return Err(session_failed().into());
    }

    // The MAC and expiry come first: they need no database access, and they prove the
    // challenge is one this server issued recently for this agent.
    let challenge_invalid = || {
        ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "challenge_invalid",
            "The challenge was not issued by this server for this agent, or it was altered. \
             Request a new challenge.",
        )
    };
    let expires_at = request.expires_at;
    if expires_at.timestamp_subsec_nanos() != 0 {
        return Err(challenge_invalid().into());
    }
    key.mac(
        request.agent_id,
        request.challenge_id,
        &nonce,
        expires_at.timestamp(),
    )
    .verify_slice(&mac)
    .map_err(|_| challenge_invalid())?;
    let now = Utc::now();
    if expires_at <= now {
        return Err(ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "challenge_expired",
            "The challenge has expired. Request a new challenge.",
        )
        .into());
    }
    // A valid MAC with a far-future expiry means the challenge key leaked. Refuse it, so
    // even then nobody can collect signatures for challenges answered much later.
    if expires_at > now + TimeDelta::seconds(CHALLENGE_LIFETIME_SECONDS + 5) {
        tracing::warn!(agent_id = %request.agent_id, "challenge with a valid MAC expires too late");
        return Err(challenge_invalid().into());
    }

    let agent: Option<AgentKey> = sqlx::query_as(
        "SELECT project_id, public_key, key_id, revoked_at IS NOT NULL AS revoked \
         FROM agents WHERE id = $1",
    )
    .bind(request.agent_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(agent) = agent else {
        return Err(session_failed().into());
    };
    let refuse = |reason, response| Refusal {
        response,
        audit: Some((reason, agent.project_id)),
    };
    if agent.key_id != request.key_id {
        return Err(refuse("unknown_key", session_failed()));
    }
    let public_key: [u8; 32] = agent
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| ApiFailure::internal("stored agent public key has the wrong length"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(ApiFailure::internal)?;
    let message = session_signing_message(
        installation_id(&state.db).await?,
        request.agent_id,
        &request.key_id,
        request.challenge_id,
        &nonce,
    );
    if verifying_key
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .is_err()
    {
        return Err(refuse("bad_signature", session_failed()));
    }
    // Only an agent that proved it holds its key learns that it is revoked.
    if agent.revoked {
        return Err(refuse("agent_revoked", agent_revoked()));
    }

    let token = Token::generate().map_err(ApiFailure::internal)?;
    let token = format!("{AGENT_SESSION_TOKEN_PREFIX}{}", token.expose());
    let mut tx = state.db.begin().await?;
    let consumed = sqlx::query(
        "INSERT INTO consumed_agent_challenges (challenge_id, expires_at) VALUES ($1, $2)",
    )
    .bind(request.challenge_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await;
    match consumed {
        Ok(_) => {}
        Err(sqlx::Error::Database(err)) if err.is_unique_violation() => {
            return Err(refuse(
                "challenge_reused",
                ApiFailure::new(
                    StatusCode::UNAUTHORIZED,
                    "challenge_used",
                    "The challenge has already been answered. Request a new challenge.",
                ),
            ));
        }
        Err(err) => return Err(err.into()),
    }
    // The share lock orders this against a revocation: either the revocation committed
    // first and is seen here, or it waits and then deletes the session created here.
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM agents WHERE id = $1 FOR SHARE")
            .bind(request.agent_id)
            .fetch_one(&mut *tx)
            .await?;
    if revoked {
        return Err(refuse("agent_revoked", agent_revoked()));
    }
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO agent_sessions (token_hash, agent_id, expires_at, source_address) \
         VALUES ($1, $2, now() + $3 * interval '1 minute', $4::inet) RETURNING expires_at",
    )
    .bind(hash_token(&token))
    .bind(request.agent_id)
    .bind(i32::try_from(AGENT_SESSION_MINUTES).map_err(ApiFailure::internal)?)
    .bind(client.map(|ip| ip.to_string()))
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::debug!(agent_id = %request.agent_id, "agent session created");
    Ok(AgentSession { token, expires_at })
}

/// Whether `value` could be a session token, so oversized input is not hashed.
pub(crate) fn plausible_session_token(value: &str) -> bool {
    value.len() == SESSION_TOKEN_LEN && value.starts_with(AGENT_SESSION_TOKEN_PREFIX)
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() > N * 2 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> ChallengeKey {
        let config = vn_config::AgentsConfig {
            challenge_key_env: "K".into(),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode([byte; 32]);
        ChallengeKey::new(
            config
                .resolve_challenge_key_with(|_| Some(encoded))
                .unwrap(),
        )
    }

    fn tag(key: &ChallengeKey, agent: u128, challenge: u128, nonce: u8, expires: i64) -> Vec<u8> {
        key.mac(
            Uuid::from_u128(agent),
            Uuid::from_u128(challenge),
            &[nonce; 32],
            expires,
        )
        .finalize()
        .into_bytes()
        .to_vec()
    }

    #[test]
    fn the_mac_covers_every_challenge_field_and_the_key() {
        let k = key(1);
        let base = tag(&k, 1, 2, 3, 100);
        assert_eq!(base, tag(&k, 1, 2, 3, 100));
        assert_ne!(base, tag(&k, 9, 2, 3, 100));
        assert_ne!(base, tag(&k, 1, 9, 3, 100));
        assert_ne!(base, tag(&k, 1, 2, 9, 100));
        assert_ne!(base, tag(&k, 1, 2, 3, 101));
        assert_ne!(base, tag(&key(2), 1, 2, 3, 100));
    }

    #[test]
    fn session_tokens_are_recognizable() {
        let token = format!(
            "{AGENT_SESSION_TOKEN_PREFIX}{}",
            Token::generate().unwrap().expose()
        );
        assert!(plausible_session_token(&token));
        assert!(!plausible_session_token(&token[1..]));
        assert!(!plausible_session_token(&format!("{token}x")));
        assert!(!plausible_session_token(
            &token.replace("vn_agent_", "vn_agenx_")
        ));
    }
}
