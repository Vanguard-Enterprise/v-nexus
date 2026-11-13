use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::OriginalUri;
use axum::http::{Method, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get, post, put};
use sqlx::PgPool;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::auth::{self, AuthService};
use crate::error::api_error;
use crate::health::{DatabaseHealth, health};
use crate::projects;

/// Shared state for request handlers.
#[derive(Clone)]
pub struct AppState {
    pub(crate) database: Arc<dyn DatabaseHealth>,
    pub(crate) db: PgPool,
    pub(crate) auth: Option<Arc<AuthService>>,
}

impl AppState {
    /// State backed by `pool`, with sign-in disabled until [`AppState::with_auth`].
    pub fn new(pool: PgPool) -> Self {
        Self {
            database: Arc::new(pool.clone()),
            db: pool,
            auth: None,
        }
    }

    /// Enables OIDC sign-in.
    pub fn with_auth(mut self, auth: AuthService) -> Self {
        self.auth = Some(Arc::new(auth));
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
/// except health and the sign-in endpoints requires a session. Remaining paths are served
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
        .route("/users", get(projects::users))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));
    let v1 = Router::new()
        .route("/health", get(health))
        .nest("/auth", auth_routes)
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
