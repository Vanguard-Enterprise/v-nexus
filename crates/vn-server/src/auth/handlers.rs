//! `/api/v1/auth` endpoints.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::{TimeDelta, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use vn_core::{InstallationRole, MeResponse};

use super::session::{self, Token};
use super::{AuthService, Principal};
use crate::audit::AuditEvent;
use crate::error::ApiFailure;
use crate::router::AppState;

/// How long a started sign-in may take before its state expires.
const LOGIN_ATTEMPT_TTL: TimeDelta = TimeDelta::minutes(10);

/// Where the browser lands when sign-in fails. The UI reads `login_error`.
const LOGIN_ERROR_PATH: &str = "/?login_error=";

fn auth_service(state: &AppState) -> Result<&AuthService, ApiFailure> {
    state.auth.as_deref().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth_not_configured",
            "Sign-in is not configured on this server. Add an `auth` section to the config file.",
        )
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQuery {
    return_to: Option<String>,
}

/// `GET /api/v1/auth/login`: sends the browser to the provider.
pub(crate) async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiFailure> {
    let auth = auth_service(&state)?;
    let start = auth.oidc.start().await.map_err(|err| {
        tracing::warn!(error = %err, "cannot start sign-in");
        ApiFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity_provider_unavailable",
            "The identity provider could not be reached. Try again shortly.",
        )
    })?;
    let return_to = safe_return_to(query.return_to.as_deref());
    let now = Utc::now();

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM oidc_login_attempts WHERE expires_at <= $1")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO oidc_login_attempts \
             (state_hash, nonce, pkce_verifier, return_to, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(session::hash_token(&start.state))
    .bind(&start.nonce)
    .bind(&start.pkce_verifier)
    .bind(&return_to)
    .bind(now)
    .bind(now + LOGIN_ATTEMPT_TTL)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let jar =
        CookieJar::new().add(auth.cookie(auth.login_cookie_name(), start.state, LOGIN_ATTEMPT_TTL));
    Ok((jar, see_other(start.url.as_str())).into_response())
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(sqlx::FromRow)]
struct LoginAttempt {
    nonce: String,
    pkce_verifier: String,
    return_to: String,
}

/// Why a callback did not produce a session. The code is shown to the UI; details go only
/// to the server log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginError {
    /// The user declined, or the provider refused to authenticate them.
    Denied,
    /// The sign-in was not started in this browser, was already used, or took too long.
    Expired,
    /// Anything else: provider errors, token validation, database failures.
    Failed,
}

impl LoginError {
    fn code(self) -> &'static str {
        match self {
            LoginError::Denied => "denied",
            LoginError::Expired => "expired",
            LoginError::Failed => "failed",
        }
    }
}

/// `GET /api/v1/auth/callback`: completes sign-in and creates the session.
pub(crate) async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiFailure> {
    let auth = auth_service(&state)?;
    let browser_state = jar
        .get(auth.login_cookie_name())
        .map(|cookie| cookie.value().to_owned());
    let previous_session = jar
        .get(auth.session_cookie_name())
        .map(|cookie| cookie.value().to_owned());
    // The login cookie is single-use whatever the outcome.
    let jar = jar.add(auth.removal(auth.login_cookie_name()));

    match complete_login(&state, auth, query, browser_state, previous_session).await {
        Ok((token, return_to)) => {
            let jar = jar.add(auth.cookie(
                auth.session_cookie_name(),
                token.expose().to_owned(),
                auth.absolute_timeout,
            ));
            Ok((jar, see_other(&return_to)).into_response())
        }
        Err(error) => {
            let location = format!("{LOGIN_ERROR_PATH}{}", error.code());
            Ok((jar, see_other(&location)).into_response())
        }
    }
}

async fn complete_login(
    state: &AppState,
    auth: &AuthService,
    query: CallbackQuery,
    browser_state: Option<String>,
    previous_session: Option<String>,
) -> Result<(Token, String), LoginError> {
    if let Some(error) = query.error {
        // `error` is an OAuth error code chosen by the provider; log only known codes so a
        // crafted callback URL cannot write arbitrary text to the log.
        let error = if error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            error
        } else {
            "invalid".into()
        };
        tracing::info!(%error, "provider returned a sign-in error");
        return Err(LoginError::Denied);
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return Err(LoginError::Failed);
    };
    let state_hash = session::hash_token(&returned_state);
    // The state must match the cookie set when this browser started the sign-in. This
    // rejects callbacks started elsewhere (login CSRF). Comparing hashes keeps the
    // comparison independent of the secret's bytes.
    match browser_state {
        Some(value) if session::hash_token(&value) == state_hash => {}
        _ => {
            tracing::info!("sign-in callback state does not match this browser");
            return Err(LoginError::Expired);
        }
    }

    let now = Utc::now();
    let attempt: Option<LoginAttempt> = sqlx::query_as(
        "DELETE FROM oidc_login_attempts WHERE state_hash = $1 AND expires_at > $2 \
         RETURNING nonce, pkce_verifier, return_to",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| failed("cannot load sign-in attempt", &err))?;
    let Some(attempt) = attempt else {
        tracing::info!("sign-in attempt is unknown, already used, or expired");
        return Err(LoginError::Expired);
    };

    let identity = auth
        .oidc
        .finish(code, attempt.pkce_verifier, &attempt.nonce)
        .await
        .map_err(|err| failed("sign-in failed", &err))?;

    let token = Token::generate().map_err(|err| failed("cannot generate session token", &err))?;
    let now = Utc::now();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| failed("cannot start transaction", &err))?;
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (issuer, subject, email, display_name, last_login_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (issuer, subject) DO UPDATE \
         SET email = EXCLUDED.email, display_name = EXCLUDED.display_name, \
             last_login_at = EXCLUDED.last_login_at \
         RETURNING id",
    )
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(&identity.email)
    .bind(&identity.display_name)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| failed("cannot store user", &err))?;

    // A fresh sign-in replaces any session this browser already had.
    if let Some(previous) = previous_session
        .as_deref()
        .and_then(session::plausible_token)
    {
        sqlx::query(
            "UPDATE sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(session::hash_token(previous))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| failed("cannot revoke previous session", &err))?;
    }
    sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| failed("cannot prune sessions", &err))?;
    let session_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sessions \
             (token_hash, user_id, installation_admin, created_at, last_seen_at, expires_at) \
         VALUES ($1, $2, $3, $4, $4, $5) RETURNING id",
    )
    .bind(token.hash())
    .bind(user_id)
    .bind(identity.installation_admin)
    .bind(now)
    .bind(now + auth.absolute_timeout)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| failed("cannot create session", &err))?;
    AuditEvent::new("auth.login", user_id)
        .details(json!({
            "session_id": session_id,
            "installation_admin": identity.installation_admin,
        }))
        .record(&mut tx)
        .await
        .map_err(|err| failed("cannot record audit event", &err))?;
    tx.commit()
        .await
        .map_err(|err| failed("cannot commit sign-in", &err))?;

    tracing::info!(
        %user_id,
        %session_id,
        installation_admin = identity.installation_admin,
        "user signed in"
    );
    Ok((token, attempt.return_to))
}

fn failed(context: &str, err: &dyn std::fmt::Display) -> LoginError {
    tracing::warn!(error = %err, "{context}");
    LoginError::Failed
}

/// `POST /api/v1/auth/logout`: revokes the session and clears its cookie. Succeeds even
/// without a session, so a stale browser can always sign out.
pub(crate) async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiFailure> {
    let Some(auth) = state.auth.as_deref() else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let token = jar
        .get(auth.session_cookie_name())
        .and_then(|cookie| session::plausible_token(cookie.value()))
        .map(session::hash_token);
    if let Some(token_hash) = token {
        let mut tx = state.db.begin().await?;
        let revoked: Option<(Uuid, Uuid)> = sqlx::query_as(
            "UPDATE sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL \
             RETURNING id, user_id",
        )
        .bind(token_hash)
        .bind(Utc::now())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((session_id, user_id)) = revoked {
            AuditEvent::new("auth.logout", user_id)
                .details(json!({ "session_id": session_id }))
                .record(&mut tx)
                .await?;
            tracing::info!(%user_id, %session_id, "user signed out");
        }
        tx.commit().await?;
    }
    let jar = jar.add(auth.removal(auth.session_cookie_name()));
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}

/// `GET /api/v1/auth/me`: the signed-in user and their installation roles.
pub(crate) async fn me(principal: Principal) -> Json<MeResponse> {
    let installation_roles = if principal.installation_admin {
        vec![InstallationRole::Admin]
    } else {
        Vec::new()
    };
    Json(MeResponse {
        user: principal.user,
        installation_roles,
        session_expires_at: principal.session_expires_at,
    })
}

fn see_other(location: &str) -> impl IntoResponse + use<> {
    let mut headers = HeaderMap::new();
    match location.parse() {
        Ok(value) => {
            headers.insert(header::LOCATION, value);
        }
        Err(_) => {
            headers.insert(header::LOCATION, header::HeaderValue::from_static("/"));
        }
    }
    (StatusCode::SEE_OTHER, headers)
}

/// Accepts only same-origin absolute paths, so sign-in cannot be used as an open
/// redirect. Anything else becomes `/`.
fn safe_return_to(value: Option<&str>) -> String {
    match value {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && !path.starts_with("/api/")
                && path.len() <= 2048
                && path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') =>
        {
            path.to_owned()
        }
        _ => "/".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_keeps_local_paths() {
        assert_eq!(
            safe_return_to(Some("/clusters/prod?tab=nodes")),
            "/clusters/prod?tab=nodes"
        );
        assert_eq!(safe_return_to(Some("/")), "/");
        assert_eq!(safe_return_to(None), "/");
    }

    #[test]
    fn return_to_rejects_other_origins_and_odd_input() {
        for value in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "evil",
            "/api/v1/auth/login",
            "/with space",
            "/new\nline",
            "/caf\u{e9}",
        ] {
            assert_eq!(safe_return_to(Some(value)), "/", "{value:?}");
        }
        assert_eq!(safe_return_to(Some(&format!("/{}", "a".repeat(2048)))), "/");
    }
}
