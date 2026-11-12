use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use vn_server::{AppState, AuthService, DatabaseHealth, PingFuture, router};

/// Database stand-in with a fixed outcome.
enum FakeDatabase {
    Up,
    Down,
    Hung,
}

impl DatabaseHealth for FakeDatabase {
    fn ping(&self) -> PingFuture<'_> {
        Box::pin(async move {
            match self {
                FakeDatabase::Up => Ok(()),
                FakeDatabase::Down => Err("connection refused".into()),
                FakeDatabase::Hung => std::future::pending().await,
            }
        })
    }
}

/// A pool that never connects; requests that reach the database fail.
fn unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .connect_lazy("postgres://vn:vn@127.0.0.1:1/vn")
        .unwrap()
}

fn app(database: impl DatabaseHealth, static_dir: Option<&Path>) -> Router {
    router(
        AppState::new(unreachable_pool()).with_health_check(database),
        static_dir,
    )
}

fn app_with_auth() -> Router {
    let config = vn_config::Config::from_yaml(
        "version: 1\n\
         server: {listen: 127.0.0.1:0}\n\
         database: {url_env: VN_DATABASE_URL}\n\
         auth:\n\
         \x20 issuer_url: http://127.0.0.1:1\n\
         \x20 client_id: vn\n\
         \x20 client_secret_env: VN_OIDC_CLIENT_SECRET\n\
         \x20 public_url: https://vn.example.com\n\
         \x20 allow_insecure_http: true\n\
         \x20 admin: {claim: groups, values: [admins]}\n",
    )
    .unwrap();
    let auth = config.auth.unwrap();
    let secret = auth
        .resolve_client_secret_with(|_| Some("test-secret".into()))
        .unwrap();
    let state = AppState::new(unreachable_pool())
        .with_health_check(FakeDatabase::Up)
        .with_auth(AuthService::new(&auth, &secret).unwrap());
    router(state, None)
}

async fn send(app: Router, method: Method, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    send_request(app, request).await
}

async fn send_request(
    app: Router,
    request: Request<Body>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, content_type, body)
}

async fn get(app: Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    send(app, Method::GET, uri).await
}

fn json_body(content_type: Option<String>, body: &[u8]) -> Value {
    assert_eq!(content_type.as_deref(), Some("application/json"));
    serde_json::from_slice(body).unwrap()
}

#[tokio::test]
async fn health_reports_ok_when_database_answers() {
    let (status, content_type, body) = get(app(FakeDatabase::Up, None), "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_body(content_type, &body),
        json!({"status": "ok", "version": env!("CARGO_PKG_VERSION"), "database": "ok"})
    );
}

#[tokio::test]
async fn health_is_503_when_database_is_down() {
    let (status, content_type, body) = get(app(FakeDatabase::Down, None), "/api/v1/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(content_type, &body),
        json!({"status": "degraded", "version": env!("CARGO_PKG_VERSION"), "database": "unavailable"})
    );
}

#[tokio::test(start_paused = true)]
async fn health_times_out_when_database_hangs() {
    let (status, content_type, body) = get(app(FakeDatabase::Hung, None), "/api/v1/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(content_type, &body)["database"], "unavailable");
}

#[tokio::test]
async fn health_is_503_when_postgres_is_unreachable() {
    // A lazy pool never connects until used, so this exercises the real PgPool check.
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .connect_lazy("postgres://vn:vn@127.0.0.1:1/vn")
        .unwrap();
    let (status, content_type, body) =
        get(router(AppState::new(pool), None), "/api/v1/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(content_type, &body)["status"], "degraded");
}

#[tokio::test]
async fn unknown_api_paths_are_json_404() {
    let dir = static_site();
    for uri in [
        "/api",
        "/api/",
        "/api/x",
        "/api/v1",
        "/api/v1/nope",
        "/api/v2/health",
    ] {
        let (status, content_type, body) = get(app(FakeDatabase::Up, Some(dir.path())), uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        let body = json_body(content_type, &body);
        assert_eq!(body["error"], "not_found", "{uri}");
        assert!(body["message"].as_str().unwrap().contains(uri), "{uri}");
    }
}

#[tokio::test]
async fn unknown_api_paths_are_json_404_without_static_dir() {
    for uri in ["/api", "/api/", "/api/x"] {
        let (status, content_type, body) = get(app(FakeDatabase::Up, None), uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(
            json_body(content_type, &body)["error"],
            "not_found",
            "{uri}"
        );
    }
}

#[tokio::test]
async fn wrong_method_on_api_route_is_json_405() {
    let (status, content_type, body) =
        send(app(FakeDatabase::Up, None), Method::POST, "/api/v1/health").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        json_body(content_type, &body)["error"],
        "method_not_allowed"
    );
}

#[tokio::test]
async fn serves_static_files_with_spa_fallback() {
    let dir = static_site();

    let (status, _, body) = get(app(FakeDatabase::Up, Some(dir.path())), "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, INDEX_HTML.as_bytes());

    let (status, content_type, body) =
        get(app(FakeDatabase::Up, Some(dir.path())), "/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("text/javascript"));
    assert_eq!(body, APP_JS.as_bytes());

    let (status, content_type, body) = get(
        app(FakeDatabase::Up, Some(dir.path())),
        "/clusters/prod/nodes",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("text/html"));
    assert_eq!(body, INDEX_HTML.as_bytes());
}

#[tokio::test]
async fn ui_routes_are_404_without_static_dir() {
    let (status, _, _) = get(app(FakeDatabase::Up, None), "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

const PROTECTED: [(&str, &str); 7] = [
    ("GET", "/api/v1/projects"),
    ("POST", "/api/v1/projects"),
    ("GET", "/api/v1/projects/prod"),
    ("GET", "/api/v1/projects/prod/members"),
    (
        "PUT",
        "/api/v1/projects/prod/members/00000000-0000-0000-0000-000000000000",
    ),
    (
        "DELETE",
        "/api/v1/projects/prod/members/00000000-0000-0000-0000-000000000000",
    ),
    ("GET", "/api/v1/users"),
];

#[tokio::test]
async fn protected_routes_are_json_401_without_a_session() {
    for (method, uri) in PROTECTED.into_iter().chain([("GET", "/api/v1/auth/me")]) {
        for (app, code) in [
            (app(FakeDatabase::Up, None), "auth_not_configured"),
            (app_with_auth(), "unauthorized"),
        ] {
            let (status, content_type, body) = send(app, method.parse().unwrap(), uri).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            assert_eq!(
                json_body(content_type, &body)["error"],
                code,
                "{method} {uri}"
            );
        }
    }
}

#[tokio::test]
async fn health_needs_no_session_when_auth_is_enabled() {
    let (status, _, _) = get(app_with_auth(), "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn login_is_503_when_auth_is_not_configured() {
    let (status, content_type, body) = get(app(FakeDatabase::Up, None), "/api/v1/auth/login").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(content_type, &body)["error"],
        "auth_not_configured"
    );
}

#[tokio::test]
async fn login_is_503_when_the_provider_is_unreachable() {
    let (status, content_type, body) = get(app_with_auth(), "/api/v1/auth/login").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(content_type, &body)["error"],
        "identity_provider_unavailable"
    );
}

#[tokio::test]
async fn cookie_requests_from_another_origin_are_rejected() {
    for origin in [Some("https://evil.example"), Some("null"), None] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/projects")
            .header(header::COOKIE, "__Host-vn_session=abc")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        let request = request
            .body(Body::from(r#"{"slug":"x","name":"x"}"#))
            .unwrap();
        let (status, content_type, body) = send_request(app_with_auth(), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{origin:?}");
        assert_eq!(json_body(content_type, &body)["error"], "csrf_rejected");
    }
}

#[tokio::test]
async fn logout_without_a_session_succeeds() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/logout")
        .header(header::ORIGIN, "https://vn.example.com")
        .body(Body::empty())
        .unwrap();
    let response = app_with_auth().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

const INDEX_HTML: &str = "<!doctype html><title>Vanguard Nexus</title>";
const APP_JS: &str = "console.log('vn');";

fn static_site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), INDEX_HTML).unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/app.js"), APP_JS).unwrap();
    dir
}
