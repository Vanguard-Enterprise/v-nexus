use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use vn_server::{AppState, DatabaseHealth, PingFuture, router};

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

fn app(database: impl DatabaseHealth, static_dir: Option<&Path>) -> Router {
    router(AppState::new(database), static_dir)
}

async fn send(app: Router, method: Method, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
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
    let (status, content_type, body) = get(app(pool, None), "/api/v1/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(content_type, &body)["status"], "degraded");
}

#[tokio::test]
async fn unknown_api_paths_are_json_404() {
    let dir = static_site();
    for uri in [
        "/api",
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

const INDEX_HTML: &str = "<!doctype html><title>Vanguard Nexus</title>";
const APP_JS: &str = "console.log('vn');";

fn static_site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), INDEX_HTML).unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/app.js"), APP_JS).unwrap();
    dir
}
