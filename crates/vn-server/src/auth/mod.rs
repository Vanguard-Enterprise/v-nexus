//! User authentication: OIDC sign-in, server-side sessions, and request guards.

mod handlers;
mod oidc;
mod session;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;
use vn_config::{AuthConfig, Secret};
use vn_core::User;

pub(crate) use handlers::{callback, login, logout, me};
pub(crate) use oidc::OidcError;
use session::{SessionStatus, SessionTimes};
pub(crate) use session::{Token, hash_token};

use crate::error::ApiFailure;
use crate::router::AppState;

/// Sign-in settings and the OIDC client, built from the `auth` config section.
pub struct AuthService {
    oidc: oidc::Oidc,
    public_origin: String,
    secure_cookies: bool,
    idle_timeout: TimeDelta,
    absolute_timeout: TimeDelta,
}

/// Error building an [`AuthService`] from configuration.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AuthSetupError(#[from] OidcError);

impl AuthService {
    /// Builds the service. Provider discovery happens on first use, so the server starts
    /// even while the provider is unreachable.
    pub fn new(config: &AuthConfig, client_secret: &Secret) -> Result<Self, AuthSetupError> {
        Ok(Self {
            oidc: oidc::Oidc::new(config, client_secret)?,
            public_origin: config.public_origin(),
            secure_cookies: config.is_https(),
            idle_timeout: TimeDelta::minutes(i64::from(config.session.idle_timeout_minutes)),
            absolute_timeout: TimeDelta::minutes(i64::from(
                config.session.absolute_timeout_minutes,
            )),
        })
    }

    /// Cookie holding the session token. The `__Host-` prefix makes browsers refuse it
    /// unless it is Secure, host-only, and scoped to `/`.
    fn session_cookie_name(&self) -> &'static str {
        if self.secure_cookies {
            "__Host-vn_session"
        } else {
            "vn_session"
        }
    }

    /// Cookie binding an in-flight sign-in to the browser that started it.
    fn login_cookie_name(&self) -> &'static str {
        if self.secure_cookies {
            "__Host-vn_login"
        } else {
            "vn_login"
        }
    }

    fn cookie(&self, name: &'static str, value: String, max_age: TimeDelta) -> Cookie<'static> {
        Cookie::build((name, value))
            .path("/")
            .http_only(true)
            .secure(self.secure_cookies)
            .same_site(SameSite::Lax)
            .max_age(::cookie::time::Duration::seconds(max_age.num_seconds()))
            .build()
    }

    fn removal(&self, name: &'static str) -> Cookie<'static> {
        let mut cookie = self.cookie(name, String::new(), TimeDelta::zero());
        cookie.make_removal();
        cookie
    }
}

/// The authenticated caller of a request.
#[derive(Debug, Clone)]
pub(crate) struct Principal {
    pub(crate) user: User,
    pub(crate) installation_admin: bool,
    pub(crate) session_expires_at: DateTime<Utc>,
}

impl Principal {
    pub(crate) fn require_admin(&self) -> Result<(), ApiFailure> {
        if self.installation_admin {
            Ok(())
        } else {
            Err(ApiFailure::forbidden(
                "This action requires the installation admin role.",
            ))
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    session_id: Uuid,
    installation_admin: bool,
    last_seen_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    user_id: Uuid,
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
}

/// Resolves the session cookie to a [`Principal`], or fails with 401.
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiFailure> {
    let Some(auth) = state.auth.as_deref() else {
        return Err(ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "auth_not_configured",
            "Sign-in is not configured on this server.",
        ));
    };
    let jar = CookieJar::from_headers(headers);
    let Some(token) = jar
        .get(auth.session_cookie_name())
        .and_then(|cookie| session::plausible_token(cookie.value()))
    else {
        return Err(ApiFailure::unauthorized("Sign in to continue."));
    };

    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.id AS session_id, s.installation_admin, s.last_seen_at, s.expires_at, \
                s.revoked_at, u.id AS user_id, u.issuer, u.subject, u.email, u.display_name \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1",
    )
    .bind(session::hash_token(token))
    .fetch_optional(&state.db)
    .await?;

    let expired = || ApiFailure::unauthorized("Your session has ended. Sign in again.");
    let Some(row) = row else {
        return Err(expired());
    };
    // A session from a previously configured issuer must not outlive the config change.
    if row.issuer != auth.oidc.issuer() {
        return Err(expired());
    }
    let times = SessionTimes {
        last_seen_at: row.last_seen_at,
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
    };
    let now = Utc::now();
    if times.status(now, auth.idle_timeout) != SessionStatus::Active {
        return Err(expired());
    }
    if times.needs_touch(now, auth.idle_timeout) {
        sqlx::query("UPDATE sessions SET last_seen_at = $2 WHERE id = $1 AND revoked_at IS NULL")
            .bind(row.session_id)
            .bind(now)
            .execute(&state.db)
            .await?;
    }

    Ok(Principal {
        user: User {
            id: row.user_id,
            issuer: row.issuer,
            subject: row.subject,
            email: row.email,
            display_name: row.display_name,
        },
        installation_admin: row.installation_admin,
        session_expires_at: row.expires_at,
    })
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiFailure;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(principal) = parts.extensions.get::<Principal>() {
            return Ok(principal.clone());
        }
        authenticate(state, &parts.headers).await
    }
}

/// Middleware for routes that require a signed-in user: answers 401 without one and
/// otherwise makes the [`Principal`] available to the handler.
pub(crate) async fn require_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    match authenticate(&state, request.headers()).await {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(failure) => failure.into_response(),
    }
}

/// CSRF protection for cookie-authenticated, state-changing API requests.
///
/// Session cookies are `SameSite=Lax`, so browsers already omit them from cross-site
/// subresource requests. As a second layer, any non-safe request that carries the session
/// cookie must have an `Origin` header equal to the configured public origin. Browsers set
/// `Origin` on every non-GET request and scripts cannot forge it, so this also covers
/// same-site attackers (sibling subdomains) that `SameSite` does not stop.
pub(crate) async fn check_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(auth) = state.auth.as_deref()
        && !is_safe_method(request.method())
        && has_cookie(request.headers(), auth.session_cookie_name())
    {
        let origin = request.headers().get(header::ORIGIN);
        if origin.is_none_or(|origin| origin.as_bytes() != auth.public_origin.as_bytes()) {
            return ApiFailure::new(
                StatusCode::FORBIDDEN,
                "csrf_rejected",
                "The request did not come from this site's origin.",
            )
            .into_response();
        }
    }
    next.run(request).await
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn has_cookie(headers: &HeaderMap, name: &str) -> bool {
    CookieJar::from_headers(headers).get(name).is_some()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn safe_methods_skip_the_origin_check() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!is_safe_method(&method), "{method}");
        }
    }

    #[test]
    fn finds_named_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; vn_session=abc"),
        );
        assert!(has_cookie(&headers, "vn_session"));
        assert!(!has_cookie(&headers, "__Host-vn_session"));
    }
}
