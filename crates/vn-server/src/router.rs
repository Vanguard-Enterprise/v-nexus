use std::path::Path;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::OriginalUri;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use vn_core::ApiError;

use crate::health::{DatabaseHealth, health};

/// Shared state for request handlers.
#[derive(Clone)]
pub struct AppState {
    pub(crate) database: Arc<dyn DatabaseHealth>,
}

impl AppState {
    pub fn new(database: impl DatabaseHealth) -> Self {
        Self {
            database: Arc::new(database),
        }
    }
}

/// Builds the application router.
///
/// API routes live under `/api/v1`; any other `/api` path gets a JSON 404. Remaining paths
/// are served from `static_dir` with `index.html` as the SPA fallback, or 404 when no
/// static directory is available.
pub fn router(state: AppState, static_dir: Option<&Path>) -> Router {
    let v1 = Router::new().route("/health", get(health));
    let api = Router::new()
        .nest("/v1", v1)
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed);

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
            .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
            .on_response(DefaultOnResponse::new().level(Level::INFO)),
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

fn api_error(status: StatusCode, code: &str, message: String) -> Response {
    (status, Json(ApiError::new(code, message))).into_response()
}
