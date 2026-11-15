use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, OriginalUri};
use axum::http::{Method, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get, post, put};
use ipnet::IpNet;
use sqlx::PgPool;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::agents::{self, AgentConnectionSettings, AgentTasks, ChallengeKey, ConnectionHub};
use crate::auth::{self, AuthService};
use crate::error::api_error;
use crate::health::{DatabaseHealth, health};
use crate::projects;
use crate::rate_limit::{RateLimit, RateLimiter};

/// Enrollment attempts per client address: a burst of 10, then one every 6 seconds.
/// Successful enrollments do not count.
const ENROLL_RATE_LIMIT: RateLimit = RateLimit {
    burst: 10,
    refill: Duration::from_secs(6),
};

/// Challenge requests per client address: a burst of 20, then one every 3 seconds.
/// Every request counts, because a challenge does not show whether it gets used.
const CHALLENGE_RATE_LIMIT: RateLimit = RateLimit {
    burst: 20,
    refill: Duration::from_secs(3),
};

/// Session requests and connection attempts per client address: a burst of 10, then one
/// every 6 seconds. Successful ones do not count.
const AGENT_AUTH_RATE_LIMIT: RateLimit = RateLimit {
    burst: 10,
    refill: Duration::from_secs(6),
};

/// Largest accepted enrollment request body.
const ENROLL_BODY_LIMIT: usize = 16 * 1024;

/// Largest accepted challenge or session request body.
const AGENT_AUTH_BODY_LIMIT: usize = 4 * 1024;

/// How long an admitted enrollment, challenge, or session request may take to send its
/// body.
const ENROLL_BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared state for request handlers.
#[derive(Clone)]
pub struct AppState {
    pub(crate) database: Arc<dyn DatabaseHealth>,
    pub(crate) db: PgPool,
    pub(crate) auth: Option<Arc<AuthService>>,
    pub(crate) trusted_proxies: Arc<[IpNet]>,
    pub(crate) enroll_limiter: Arc<RateLimiter>,
    pub(crate) enroll_body_timeout: Duration,
    /// Keys challenge MACs. Without it the challenge, session, and connect endpoints
    /// answer 503.
    pub(crate) challenge_key: Option<Arc<ChallengeKey>>,
    pub(crate) challenge_limiter: Arc<RateLimiter>,
    pub(crate) session_limiter: Arc<RateLimiter>,
    pub(crate) connect_limiter: Arc<RateLimiter>,
    pub(crate) agent_settings: AgentConnectionSettings,
    pub(crate) agent_hub: Arc<ConnectionHub>,
}

impl AppState {
    /// State backed by `pool`, with sign-in disabled until [`AppState::with_auth`].
    pub fn new(pool: PgPool) -> Self {
        Self {
            database: Arc::new(pool.clone()),
            db: pool,
            auth: None,
            trusted_proxies: Arc::new([]),
            enroll_limiter: Arc::new(RateLimiter::new(ENROLL_RATE_LIMIT)),
            enroll_body_timeout: ENROLL_BODY_TIMEOUT,
            challenge_key: None,
            challenge_limiter: Arc::new(RateLimiter::new(CHALLENGE_RATE_LIMIT)),
            session_limiter: Arc::new(RateLimiter::new(AGENT_AUTH_RATE_LIMIT)),
            connect_limiter: Arc::new(RateLimiter::new(AGENT_AUTH_RATE_LIMIT)),
            agent_settings: AgentConnectionSettings::default(),
            agent_hub: Arc::default(),
        }
    }

    /// Enables agent connections, with MACs keyed by the configured challenge key.
    pub fn with_agent_challenge_key(mut self, key: vn_config::ChallengeKey) -> Self {
        self.challenge_key = Some(Arc::new(ChallengeKey::new(key)));
        self
    }

    /// Changes agent connection timings and limits, so tests need not wait for the
    /// defaults.
    pub fn with_agent_connection_settings(mut self, settings: AgentConnectionSettings) -> Self {
        self.agent_settings = settings;
        self
    }

    /// Prepares for agent connections and starts their background tasks: closes
    /// connection rows a previous server process left open, deletes expired sessions,
    /// and starts the revocation listener and periodic cleanup. Call it once at startup,
    /// before serving, and [`AgentTasks::shutdown`] after serving, before closing the
    /// pool.
    pub async fn start_agent_tasks(&self) -> sqlx::Result<AgentTasks> {
        agents::start_tasks(&self.db, self.agent_hub.clone()).await
    }

    /// Believes `X-Forwarded-For` from these reverse proxies when resolving client
    /// addresses.
    pub fn with_trusted_proxies(mut self, proxies: impl Into<Arc<[IpNet]>>) -> Self {
        self.trusted_proxies = proxies.into();
        self
    }

    /// Enables OIDC sign-in.
    pub fn with_auth(mut self, auth: AuthService) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    /// Changes how long an enrollment attempt may take to send its body (10 seconds by
    /// default), so tests need not wait for the default.
    pub fn with_enroll_body_timeout(mut self, timeout: Duration) -> Self {
        self.enroll_body_timeout = timeout;
        self
    }

    /// Replaces the check behind the health endpoint, so tests can simulate database
    /// outages.
    pub fn with_health_check(mut self, check: impl DatabaseHealth) -> Self {
        self.database = Arc::new(check);
        self
    }
}

/// Builds the application router.
///
/// API routes live under `/api/v1`; any other `/api` path gets a JSON 404. Every API route
/// except health, the sign-in endpoints, and the agent endpoints requires a session.
/// Agents authenticate with their own credentials, never a session. Remaining paths are served
/// from `static_dir` with `index.html` as the SPA fallback, or 404 when no static
/// directory is available.
pub fn router(state: AppState, static_dir: Option<&Path>) -> Router {
    let auth_routes = Router::new()
        .route("/login", get(auth::login))
        .route("/callback", get(auth::callback))
        .route("/logout", post(auth::logout))
        .route("/me", get(auth::me));
    // Routes added here are only reachable with a valid session.
    let protected = Router::new()
        .route("/projects", get(projects::list).post(projects::create))
        .route("/projects/{slug}", get(projects::show))
        .route("/projects/{slug}/members", get(projects::members))
        .route(
            "/projects/{slug}/members/{user_id}",
            put(projects::assign).delete(projects::unassign),
        )
        .route(
            "/projects/{slug}/enrollment-tokens",
            get(agents::list_tokens).post(agents::create_token),
        )
        .route(
            "/projects/{slug}/enrollment-tokens/{token_id}/revoke",
            post(agents::revoke_token),
        )
        .route("/projects/{slug}/agents", get(agents::list))
        .route(
            "/projects/{slug}/agents/{agent_id}/revoke",
            post(agents::revoke),
        )
        .route("/users", get(projects::users))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));
    let agent_routes = Router::new()
        .route("/info", get(agents::info))
        .route(
            "/manifests/kubernetes.yaml",
            get(agents::manifest::kubernetes),
        )
        .route(
            "/enroll",
            post(agents::enroll).layer(DefaultBodyLimit::max(ENROLL_BODY_LIMIT)),
        )
        .route(
            "/auth/challenge",
            post(agents::challenge).layer(DefaultBodyLimit::max(AGENT_AUTH_BODY_LIMIT)),
        )
        .route(
            "/auth/session",
            post(agents::session).layer(DefaultBodyLimit::max(AGENT_AUTH_BODY_LIMIT)),
        )
        .route("/connect", get(agents::connect));
    let v1 = Router::new()
        .route("/health", get(health))
        .nest("/auth", auth_routes)
        .nest("/agent", agent_routes)
        .merge(protected);
    let api = Router::new()
        .nest("/v1", v1)
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::check_origin,
        ));

    // `nest` covers `/api` and `/api/...` but not `/api/` itself, which would otherwise fall
    // through to the UI.
    let app = Router::new()
        .nest("/api", api)
        .route("/api/", any(api_not_found))
        .with_state(state);
    let app = match static_dir {
        Some(dir) => {
            let index = ServeFile::new(dir.join("index.html"));
            app.fallback_service(ServeDir::new(dir).fallback(index))
        }
        None => app.fallback(|| async { StatusCode::NOT_FOUND }),
    };

    app.layer(
        TraceLayer::new_for_http()
            .make_span_with(request_span)
            .on_response(DefaultOnResponse::new().level(Level::INFO)),
    )
}

/// Request span for logs. Records the path but not the query string, which can carry
/// secrets such as the OAuth authorization code and state on the sign-in callback.
fn request_span(request: &axum::http::Request<axum::body::Body>) -> tracing::Span {
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        version = ?request.version(),
    )
}

async fn api_not_found(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("no API route for {method} {}", uri.path()),
    )
}

async fn api_method_not_allowed(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        format!("{method} is not allowed for {}", uri.path()),
    )
}
