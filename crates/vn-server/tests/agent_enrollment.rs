//! Enrollment token, agent enrollment, and agent revocation tests against a real
//! PostgreSQL database.
//!
//! These tests need PostgreSQL. Set `DATABASE_URL` to a server where the user may create
//! databases (for example the Compose database, `postgres://vn:vn@localhost:5432/vn`).
//! Each test creates and drops its own database. Without `DATABASE_URL` the tests pass
//! after printing that they were skipped.
//!
//! Browser sessions are inserted directly instead of signing in through a provider: the
//! sign-in flow has its own tests in `auth_flow.rs`.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};
use tower::ServiceExt;
use uuid::Uuid;
use vn_server::{AppState, AuthService, router};

const ISSUER: &str = "https://id.example.com";
const PUBLIC_ORIGIN: &str = "https://vn.example.com";
const SESSION_COOKIE: &str = "__Host-vn_session";
const FINGERPRINT: &str = "6f1c2a8e-8a3b-4c55-9d1e-0b7c1f2e3d4a";
const REVOKED_CHANNEL: &str = "vn_agent_revoked";

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/// A freshly migrated database that exists for one test.
struct TestDb {
    pool: PgPool,
    admin_url: String,
    name: String,
}

impl TestDb {
    async fn create() -> Option<Self> {
        let Ok(admin_url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL is not set");
            return None;
        };
        let name = format!("vn_test_{}", random_hex(8));
        let mut admin = PgConnection::connect(&admin_url)
            .await
            .expect("connect to DATABASE_URL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .expect("create test database");
        admin.close().await.ok();

        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(&database_url(&admin_url, &name))
            .await
            .expect("connect to test database");
        vn_server::MIGRATOR.run(&pool).await.expect("migrate");
        Some(Self {
            pool,
            admin_url,
            name,
        })
    }

    async fn drop_database(self) {
        self.pool.close().await;
        if let Ok(mut admin) = PgConnection::connect(&self.admin_url).await {
            let sql = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name);
            sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                .execute(&mut admin)
                .await
                .ok();
        }
    }
}

/// `admin_url` pointed at database `name`.
fn database_url(admin_url: &str, name: &str) -> String {
    let mut url = url::Url::parse(admin_url).expect("DATABASE_URL is a URL");
    url.set_path(name);
    url.into()
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).unwrap();
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// VN under test
// ---------------------------------------------------------------------------

struct Harness {
    db: TestDb,
    app: Router,
    installation_id: Uuid,
    /// Session of an installation admin.
    admin: String,
    admin_id: Uuid,
}

impl Harness {
    async fn start() -> Option<Self> {
        Self::start_with(Vec::new()).await
    }

    async fn start_with(trusted_proxies: Vec<ipnet::IpNet>) -> Option<Self> {
        let db = TestDb::create().await?;
        let config = vn_config::Config::from_yaml(&format!(
            "version: 1
server: {{listen: 127.0.0.1:0}}
database: {{url_env: VN_DATABASE_URL}}
auth:
  issuer_url: {ISSUER}
  client_id: vn-test
  client_secret_env: VN_OIDC_CLIENT_SECRET
  public_url: {PUBLIC_ORIGIN}
  admin: {{claim: groups, values: [vn-admins]}}
"
        ))
        .unwrap();
        let auth = config.auth.unwrap();
        let secret = auth
            .resolve_client_secret_with(|_| Some("unused".into()))
            .unwrap();
        // Provider discovery is lazy, so no provider is needed while nobody signs in.
        let state = AppState::new(db.pool.clone())
            .with_auth(AuthService::new(&auth, &secret).unwrap())
            .with_trusted_proxies(trusted_proxies);
        let app = router(state, None);
        let installation_id = sqlx::query_scalar("SELECT installation_id FROM installation")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        let mut h = Self {
            db,
            app,
            installation_id,
            admin: String::new(),
            admin_id: Uuid::nil(),
        };
        (h.admin, h.admin_id) = h.session("alice", true).await;
        let created = h
            .write(
                &h.admin,
                Method::POST,
                "/api/v1/projects",
                json!({"slug": "prod", "name": "Production"}),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json);
        Some(h)
    }

    /// Creates a user and a session for them, as a completed sign-in would.
    async fn session(&self, subject: &str, admin: bool) -> (String, Uuid) {
        let user_id: Uuid =
            sqlx::query_scalar("INSERT INTO users (issuer, subject) VALUES ($1, $2) RETURNING id")
                .bind(ISSUER)
                .bind(subject)
                .fetch_one(&self.db.pool)
                .await
                .unwrap();
        let token = random_hex(32);
        sqlx::query(
            "INSERT INTO sessions \
                 (token_hash, user_id, installation_admin, created_at, last_seen_at, expires_at) \
             VALUES ($1, $2, $3, now(), now(), now() + interval '12 hours')",
        )
        .bind(Sha256::digest(token.as_bytes()).to_vec())
        .bind(user_id)
        .bind(admin)
        .execute(&self.db.pool)
        .await
        .unwrap();
        (token, user_id)
    }

    async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self.app.clone().oneshot(request).await.unwrap();
        TestResponse::read(response).await
    }

    async fn get(&self, session: &str, uri: &str) -> TestResponse {
        self.send(
            Request::get(uri)
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// A state-changing request as the browser UI sends it.
    async fn write(&self, session: &str, method: Method, uri: &str, body: Value) -> TestResponse {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
            .header(header::ORIGIN, PUBLIC_ORIGIN);
        let request = if body.is_null() {
            request.body(Body::empty())
        } else {
            request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
        };
        self.send(request.unwrap()).await
    }

    /// Creates a token for a new cluster in `prod` and returns the token string.
    async fn new_cluster_token(&self) -> String {
        let created = self
            .create_token(json!({
                "kind": "kubernetes",
                "target": {"type": "new_cluster", "display_name": "east"},
            }))
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json);
        created.json["secret"].as_str().unwrap().to_owned()
    }

    /// Creates a token replacing the agent of `source_id` and returns the token string.
    async fn replacement_token(&self, source_id: &str) -> String {
        let created = self
            .create_token(json!({
                "kind": "kubernetes",
                "target": {"type": "replace_source", "source_id": source_id},
            }))
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json);
        created.json["secret"].as_str().unwrap().to_owned()
    }

    async fn create_token(&self, body: Value) -> TestResponse {
        self.write(
            &self.admin,
            Method::POST,
            "/api/v1/projects/prod/enrollment-tokens",
            body,
        )
        .await
    }

    /// Enrolls as an agent would: no cookie, no `Origin`, from `peer`.
    async fn enroll_from(
        &self,
        body: &Value,
        peer: &str,
        forwarded_for: Option<&str>,
    ) -> TestResponse {
        self.send(enroll_request(body, peer, forwarded_for)).await
    }

    async fn enroll(&self, body: &Value) -> TestResponse {
        self.enroll_from(body, "192.0.2.10:40000", None).await
    }

    /// Enrolls a new agent with a fresh key and returns the response body.
    async fn enroll_new(&self, token: &str) -> Value {
        let key = AgentKey::generate();
        let response = self
            .enroll(&key.body(token, self.installation_id, FINGERPRINT))
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{:?}", response.json);
        response.json
    }

    async fn audit(&self) -> Vec<(String, Option<Uuid>, Option<Uuid>, Value)> {
        sqlx::query_as(
            "SELECT action, actor_user_id, agent_id, details FROM audit_events ORDER BY id",
        )
        .fetch_all(&self.db.pool)
        .await
        .unwrap()
    }

    async fn audit_actions(&self) -> Vec<String> {
        self.audit().await.into_iter().map(|(a, ..)| a).collect()
    }

    /// Reasons recorded for refused enrollments, in order.
    async fn failure_reasons(&self) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT details->>'reason' FROM audit_events \
             WHERE action = 'agent.enroll_failed' ORDER BY id",
        )
        .fetch_all(&self.db.pool)
        .await
        .unwrap()
    }

    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(&self.db.pool)
            .await
            .unwrap()
    }

    /// Listens for revocation notifications on its own connection, outside the pool, so
    /// it does not hold up closing the pool.
    async fn listener(&self) -> PgListener {
        let url = database_url(&self.db.admin_url, &self.db.name);
        let mut listener = PgListener::connect(&url).await.unwrap();
        listener.listen(REVOKED_CHANNEL).await.unwrap();
        listener
    }

    async fn finish(self) {
        self.db.drop_database().await;
    }
}

fn enroll_request(body: &Value, peer: &str, forwarded_for: Option<&str>) -> Request<Body> {
    let mut request =
        Request::post("/api/v1/agent/enroll").header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = forwarded_for {
        request = request.header("x-forwarded-for", value);
    }
    let mut request = request.body(Body::from(body.to_string())).unwrap();
    let peer: SocketAddr = peer.parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
}

impl TestResponse {
    async fn read(response: axum::response::Response) -> Self {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Self {
            status,
            headers,
            json,
        }
    }

    fn assert_generic_failure(&self) {
        assert_eq!(self.status, StatusCode::UNAUTHORIZED, "{:?}", self.json);
        assert_eq!(self.json["error"], "enrollment_failed");
    }
}

/// An agent's Ed25519 key pair.
struct AgentKey(SigningKey);

impl AgentKey {
    fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        Self(SigningKey::from_bytes(&seed))
    }

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// The enrollment request body, signed for `signed_installation`.
    fn body_signed_for(
        &self,
        token: &str,
        installation_id: Uuid,
        signed_installation: Uuid,
        fingerprint: &str,
    ) -> Value {
        let token_id = token_id(token);
        let public_key = self.public_key();
        let message =
            vn_core::enrollment_signing_message(signed_installation, token_id, &public_key);
        let signature = self.0.sign(&message);
        json!({
            "token": token,
            "installation_id": installation_id,
            "kind": "kubernetes",
            "public_key": URL_SAFE_NO_PAD.encode(public_key),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            "agent_version": "0.1.0",
            "protocol_versions": [1],
            "cluster_fingerprint": fingerprint,
        })
    }

    fn body(&self, token: &str, installation_id: Uuid, fingerprint: &str) -> Value {
        self.body_signed_for(token, installation_id, installation_id, fingerprint)
    }
}

/// The token ID embedded in a token string.
fn token_id(token: &str) -> Uuid {
    let rest = token.strip_prefix("vn_enroll_").expect("token prefix");
    Uuid::try_parse(&rest[..32]).expect("token ID")
}

macro_rules! harness {
    ($expr:expr) => {
        match $expr.await {
            Some(h) => h,
            None => return,
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_creates_a_token_and_an_agent_enrolls_with_it() {
    let h = harness!(Harness::start());

    let created = h
        .create_token(json!({
            "kind": "kubernetes",
            "target": {"type": "new_cluster", "display_name": "  east  "},
        }))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json);
    let token = created.json["secret"].as_str().unwrap().to_owned();
    assert!(token.starts_with("vn_enroll_"), "{token}");
    assert_eq!(created.json["installation_id"], json!(h.installation_id));
    let meta = &created.json["token"];
    assert_eq!(meta["id"], json!(token_id(&token)));
    assert_eq!(meta["status"], "active");
    assert_eq!(meta["kind"], "kubernetes");
    assert_eq!(
        meta["target"],
        json!({"type": "new_cluster", "display_name": "east"})
    );
    assert_eq!(meta["created_by"], json!(h.admin_id));
    let lifetime: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - created_at)::float8 FROM enrollment_tokens",
    )
    .fetch_one(&h.db.pool)
    .await
    .unwrap();
    assert_eq!(lifetime, 3600.0);

    // Only a hash of the secret is stored.
    let secret = &token[token.len() - 43..];
    let stored: Vec<u8> = sqlx::query_scalar("SELECT secret_hash FROM enrollment_tokens")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(stored, Sha256::digest(secret.as_bytes()).to_vec());

    // The agent learns the installation ID without signing in.
    let info = h
        .send(
            Request::get("/api/v1/agent/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(
        info.json,
        json!({"installation_id": h.installation_id, "protocol_versions": [1]})
    );

    let key = AgentKey::generate();
    let enrolled = h
        .enroll(&key.body(&token, h.installation_id, FINGERPRINT))
        .await;
    assert_eq!(enrolled.status, StatusCode::CREATED, "{:?}", enrolled.json);
    let agent_id = enrolled.json["agent_id"].as_str().unwrap().to_owned();
    assert_eq!(enrolled.json["installation_id"], json!(h.installation_id));
    let expected_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_key()));
    assert_eq!(enrolled.json["key_id"], json!(expected_key_id));

    // The cluster, its one whole-cluster source, and the agent record.
    let (cluster_name, fingerprint): (String, String) =
        sqlx::query_as("SELECT display_name, fingerprint FROM clusters")
            .fetch_one(&h.db.pool)
            .await
            .unwrap();
    assert_eq!(
        (cluster_name.as_str(), fingerprint.as_str()),
        ("east", FINGERPRINT)
    );
    let (scope, epoch): (String, i64) = sqlx::query_as("SELECT scope, sync_epoch FROM sources")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!((scope.as_str(), epoch), ("cluster", 0));
    let public_key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(public_key, key.public_key());

    let agents = h.get(&h.admin, "/api/v1/projects/prod/agents").await;
    assert_eq!(agents.status, StatusCode::OK);
    let agent = &agents.json["agents"][0];
    assert_eq!(agent["id"], json!(agent_id));
    assert_eq!(agent["status"], "active");
    assert_eq!(agent["kind"], "kubernetes");
    assert_eq!(agent["cluster_id"], enrolled.json["cluster_id"]);
    assert_eq!(agent["cluster_name"], "east");
    assert_eq!(agent["source_id"], enrolled.json["source_id"]);
    assert_eq!(agent["key_id"], json!(expected_key_id));
    assert_eq!(agent["cluster_fingerprint"], FINGERPRINT);
    assert_eq!(agent["agent_version"], "0.1.0");
    assert_eq!(agent["protocol_versions"], json!([1]));
    assert_eq!(agent["enrollment_token_id"], json!(token_id(&token)));
    assert_eq!(agent["enrolled_by"], json!(h.admin_id));
    assert_eq!(agent["source_address"], "192.0.2.10");
    assert_eq!(agent["revoked_at"], Value::Null);

    let tokens = h
        .get(&h.admin, "/api/v1/projects/prod/enrollment-tokens")
        .await;
    assert_eq!(tokens.json["tokens"][0]["status"], "used");

    // Audited, and the secret appears nowhere in the database's audit trail.
    let audit = h.audit().await;
    let actions: Vec<&str> = audit.iter().map(|(a, ..)| a.as_str()).collect();
    assert_eq!(
        actions,
        ["project.create", "enrollment_token.create", "agent.enroll"]
    );
    let (_, actor, audited_agent, details) = &audit[2];
    assert_eq!(*actor, None);
    assert_eq!(audited_agent.map(|id| id.to_string()), Some(agent_id));
    assert_eq!(details["token_created_by"], json!(h.admin_id));
    assert_eq!(details["source_address"], "192.0.2.10");
    let all = serde_json::to_string(&audit.iter().map(|(.., d)| d).collect::<Vec<_>>()).unwrap();
    assert!(!all.contains(secret), "{all}");

    h.finish().await;
}

#[tokio::test]
async fn a_token_enrolls_only_once() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    h.enroll_new(&token).await;

    let again = h
        .enroll(&AgentKey::generate().body(&token, h.installation_id, FINGERPRINT))
        .await;
    again.assert_generic_failure();
    assert_eq!(h.count("agents").await, 1);
    assert_eq!(h.count("clusters").await, 1);
    assert_eq!(h.failure_reasons().await, ["token_used"]);

    h.finish().await;
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    sqlx::query(
        "UPDATE enrollment_tokens SET created_at = now() - interval '2 hours', \
             expires_at = now() - interval '1 second'",
    )
    .execute(&h.db.pool)
    .await
    .unwrap();

    let response = h
        .enroll(&AgentKey::generate().body(&token, h.installation_id, FINGERPRINT))
        .await;
    response.assert_generic_failure();
    assert_eq!(h.count("agents").await, 0);
    assert_eq!(h.failure_reasons().await, ["token_expired"]);
    let tokens = h
        .get(&h.admin, "/api/v1/projects/prod/enrollment-tokens")
        .await;
    assert_eq!(tokens.json["tokens"][0]["status"], "expired");

    h.finish().await;
}

#[tokio::test]
async fn an_unused_token_can_be_revoked() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    let uri = format!(
        "/api/v1/projects/prod/enrollment-tokens/{}/revoke",
        token_id(&token)
    );

    let revoked = h.write(&h.admin, Method::POST, &uri, Value::Null).await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.json);
    assert_eq!(revoked.json["status"], "revoked");
    assert_eq!(revoked.json["revoked_by"], json!(h.admin_id));

    let response = h
        .enroll(&AgentKey::generate().body(&token, h.installation_id, FINGERPRINT))
        .await;
    response.assert_generic_failure();
    assert_eq!(h.count("agents").await, 0);
    assert_eq!(h.failure_reasons().await, ["token_revoked"]);

    let again = h.write(&h.admin, Method::POST, &uri, Value::Null).await;
    assert_eq!(again.status, StatusCode::CONFLICT);

    // A used token cannot be revoked: the agent is revoked instead.
    let used = h.new_cluster_token().await;
    h.enroll_new(&used).await;
    let uri = format!(
        "/api/v1/projects/prod/enrollment-tokens/{}/revoke",
        token_id(&used)
    );
    let response = h.write(&h.admin, Method::POST, &uri, Value::Null).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert!(
        response.json["message"]
            .as_str()
            .unwrap()
            .contains("already been used"),
        "{:?}",
        response.json
    );

    let unknown = format!(
        "/api/v1/projects/prod/enrollment-tokens/{}/revoke",
        Uuid::from_u128(7)
    );
    let response = h.write(&h.admin, Method::POST, &unknown, Value::Null).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);

    let actions = h.audit_actions().await;
    assert_eq!(
        actions
            .iter()
            .filter(|a| *a == "enrollment_token.revoke")
            .count(),
        1
    );

    h.finish().await;
}

#[tokio::test]
async fn a_bad_signature_is_refused_without_using_the_token() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;

    // Signed by a different key than the one registered.
    let mut body = AgentKey::generate().body(&token, h.installation_id, FINGERPRINT);
    let other = AgentKey::generate();
    body["public_key"] = json!(URL_SAFE_NO_PAD.encode(other.public_key()));
    h.enroll(&body).await.assert_generic_failure();

    // Signed over a different token ID.
    let other_token = h.new_cluster_token().await;
    let key = AgentKey::generate();
    let mut body = key.body(&other_token, h.installation_id, FINGERPRINT);
    body["token"] = json!(token);
    h.enroll(&body).await.assert_generic_failure();

    assert_eq!(h.count("agents").await, 0);
    assert_eq!(
        h.failure_reasons().await,
        ["bad_signature", "bad_signature"]
    );

    // The token is still usable by its rightful agent.
    h.enroll_new(&token).await;

    h.finish().await;
}

#[tokio::test]
async fn the_installation_id_must_match() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    let key = AgentKey::generate();
    let elsewhere = Uuid::from_u128(42);

    // An agent configured for another installation.
    let response = h.enroll(&key.body(&token, elsewhere, FINGERPRINT)).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.json["error"], "wrong_installation");

    // A signature made for another installation does not verify here.
    let response = h
        .enroll(&key.body_signed_for(&token, h.installation_id, elsewhere, FINGERPRINT))
        .await;
    response.assert_generic_failure();

    assert_eq!(h.count("agents").await, 0);
    assert_eq!(
        h.failure_reasons().await,
        ["wrong_installation", "bad_signature"]
    );
    h.enroll_new(&token).await;

    h.finish().await;
}

#[tokio::test]
async fn refusals_do_not_reveal_whether_a_token_exists() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    let key = AgentKey::generate();

    let unknown_id = format!(
        "vn_enroll_{}{}",
        Uuid::from_u128(9).simple(),
        &token[token.len() - 44..]
    );
    let wrong_secret = format!("{}{}", &token[..token.len() - 43], "A".repeat(43));
    let mut bodies = Vec::new();
    for candidate in [unknown_id.as_str(), wrong_secret.as_str(), "vn_enroll_nope"] {
        let mut body = key.body(&token, h.installation_id, FINGERPRINT);
        body["token"] = json!(candidate);
        // Sign for the token ID the request names, so the signature itself is valid.
        if candidate != "vn_enroll_nope" {
            body = key.body(candidate, h.installation_id, FINGERPRINT);
        }
        let response = h.enroll(&body).await;
        response.assert_generic_failure();
        bodies.push(response.json);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    assert_eq!(
        h.failure_reasons().await,
        ["unknown_token", "wrong_secret", "malformed_token"]
    );
    h.enroll_new(&token).await;

    h.finish().await;
}

#[tokio::test]
async fn replacement_revokes_the_previous_agent_in_the_same_transaction() {
    let h = harness!(Harness::start());
    let first = h.enroll_new(&h.new_cluster_token().await).await;
    let source_id = first["source_id"].as_str().unwrap();
    let first_id = first["agent_id"].as_str().unwrap();
    sqlx::query("UPDATE sources SET sync_epoch = 5")
        .execute(&h.db.pool)
        .await
        .unwrap();
    let mut listener = h.listener().await;

    let token = h.replacement_token(source_id).await;
    let second = h.enroll_new(&token).await;
    assert_eq!(second["source_id"], first["source_id"]);
    assert_eq!(second["cluster_id"], first["cluster_id"]);
    assert_ne!(second["agent_id"], first["agent_id"]);

    let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("revocation notification")
        .unwrap();
    assert_eq!(notification.payload(), first_id);

    let agents = h.get(&h.admin, "/api/v1/projects/prod/agents").await;
    let agents = agents.json["agents"].as_array().unwrap().clone();
    assert_eq!(agents.len(), 2);
    let old = agents.iter().find(|a| a["id"] == json!(first_id)).unwrap();
    assert_eq!(old["status"], "revoked");
    assert_eq!(old["revocation_reason"], "replaced");
    let new = agents
        .iter()
        .find(|a| a["id"] == second["agent_id"])
        .unwrap();
    assert_eq!(new["status"], "active");

    // The epoch stays on the source, so the replacement's observations order later.
    let epoch: i64 = sqlx::query_scalar("SELECT sync_epoch FROM sources")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(epoch, 5);
    assert_eq!(h.count("sources").await, 1);
    assert_eq!(h.count("clusters").await, 1);

    let audit = h.audit().await;
    let tail: Vec<(&str, Option<String>)> = audit[audit.len() - 2..]
        .iter()
        .map(|(action, _, agent, _)| (action.as_str(), agent.map(|id| id.to_string())))
        .collect();
    assert_eq!(
        tail,
        [
            ("agent.revoke", Some(first_id.to_owned())),
            (
                "agent.enroll",
                second["agent_id"].as_str().map(str::to_owned)
            ),
        ]
    );
    assert_eq!(audit[audit.len() - 2].3["reason"], "replaced");

    h.finish().await;
}

#[tokio::test]
async fn replacement_from_another_cluster_is_refused() {
    let h = harness!(Harness::start());
    let first = h.enroll_new(&h.new_cluster_token().await).await;
    let token = h
        .replacement_token(first["source_id"].as_str().unwrap())
        .await;

    let response = h
        .enroll(&AgentKey::generate().body(&token, h.installation_id, "another-cluster-uid"))
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{:?}", response.json);
    assert_eq!(response.json["error"], "fingerprint_mismatch");
    assert_eq!(h.failure_reasons().await, ["fingerprint_mismatch"]);

    // Nothing changed: the first agent is active and the token is unused.
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE revoked_at IS NULL")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(active, 1);
    assert_eq!(h.count("agents").await, 1);
    let used: bool =
        sqlx::query_scalar("SELECT used_at IS NOT NULL FROM enrollment_tokens WHERE id = $1")
            .bind(token_id(&token))
            .fetch_one(&h.db.pool)
            .await
            .unwrap();
    assert!(!used);

    h.finish().await;
}

#[tokio::test]
async fn concurrent_use_of_one_token_enrolls_exactly_one_agent() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;

    let attempts: Vec<_> = (0..8)
        .map(|i| {
            let app = h.app.clone();
            let body = AgentKey::generate().body(&token, h.installation_id, FINGERPRINT);
            tokio::spawn(async move {
                let peer = format!("192.0.2.{}:40000", 100 + i);
                let response = app
                    .oneshot(enroll_request(&body, &peer, None))
                    .await
                    .unwrap();
                response.status()
            })
        })
        .collect();
    let mut statuses = Vec::new();
    for attempt in attempts {
        statuses.push(attempt.await.unwrap());
    }
    let created = statuses
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    let refused = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!((created, refused), (1, 7), "{statuses:?}");
    assert_eq!(h.count("agents").await, 1);
    assert_eq!(h.count("clusters").await, 1);
    assert_eq!(h.count("sources").await, 1);
    assert_eq!(h.failure_reasons().await, ["token_used"; 7]);

    h.finish().await;
}

#[tokio::test]
async fn only_installation_admins_manage_tokens_and_agents() {
    let h = harness!(Harness::start());
    let agent = h.enroll_new(&h.new_cluster_token().await).await;
    let (operator, operator_id) = h.session("olivia", false).await;
    let assign = h
        .write(
            &h.admin,
            Method::PUT,
            &format!("/api/v1/projects/prod/members/{operator_id}"),
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(assign.status, StatusCode::OK);

    let create = h
        .write(
            &operator,
            Method::POST,
            "/api/v1/projects/prod/enrollment-tokens",
            json!({"kind": "kubernetes", "target": {"type": "new_cluster", "display_name": "x"}}),
        )
        .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN, "{:?}", create.json);
    let list = h
        .get(&operator, "/api/v1/projects/prod/enrollment-tokens")
        .await;
    assert_eq!(list.status, StatusCode::FORBIDDEN);
    let revoke_uri = format!(
        "/api/v1/projects/prod/agents/{}/revoke",
        agent["agent_id"].as_str().unwrap()
    );
    let revoke = h
        .write(&operator, Method::POST, &revoke_uri, Value::Null)
        .await;
    assert_eq!(revoke.status, StatusCode::FORBIDDEN);

    // Members may see the project's agents.
    let agents = h.get(&operator, "/api/v1/projects/prod/agents").await;
    assert_eq!(agents.status, StatusCode::OK);
    assert_eq!(agents.json["agents"].as_array().unwrap().len(), 1);

    // Users without a role cannot tell that the project exists.
    let (outsider, _) = h.session("mallory", false).await;
    let agents = h.get(&outsider, "/api/v1/projects/prod/agents").await;
    assert_eq!(agents.status, StatusCode::NOT_FOUND);

    // Without a session, or from another origin, nothing is created.
    let anonymous = h
        .send(
            Request::post("/api/v1/projects/prod/enrollment-tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"kind": "kubernetes", "target": {"type": "new_cluster", "display_name": "x"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let cross_site = h
        .send(
            Request::post("/api/v1/projects/prod/enrollment-tokens")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={}", h.admin))
                .header(header::ORIGIN, "https://evil.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"kind": "kubernetes", "target": {"type": "new_cluster", "display_name": "x"}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(cross_site.status, StatusCode::FORBIDDEN);
    assert_eq!(cross_site.json["error"], "csrf_rejected");
    assert_eq!(h.count("enrollment_tokens").await, 1);

    h.finish().await;
}

#[tokio::test]
async fn token_requests_are_validated() {
    let h = harness!(Harness::start());
    let new_cluster = json!({"type": "new_cluster", "display_name": "east"});
    for (body, status) in [
        (
            json!({"kind": "kubernetes", "target": new_cluster, "expires_in_minutes": 0}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"kind": "kubernetes", "target": new_cluster, "expires_in_minutes": 1441}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"kind": "kubernetes", "target": {"type": "new_cluster", "display_name": "  "}}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"kind": "docker", "target": new_cluster}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"kind": "kubernetes", "target": {"type": "replace_source", "source_id": Uuid::from_u128(1)}}),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = h.create_token(body.clone()).await;
        assert_eq!(response.status, status, "{body} {:?}", response.json);
    }
    assert_eq!(h.count("enrollment_tokens").await, 0);

    let longest = h
        .create_token(
            json!({"kind": "kubernetes", "target": new_cluster, "expires_in_minutes": 1440}),
        )
        .await;
    assert_eq!(longest.status, StatusCode::CREATED);

    // A source in another project cannot be targeted.
    let agent = h.enroll_new(&h.new_cluster_token().await).await;
    let other = h
        .write(
            &h.admin,
            Method::POST,
            "/api/v1/projects",
            json!({"slug": "dev", "name": "Development"}),
        )
        .await;
    assert_eq!(other.status, StatusCode::CREATED);
    let response = h
        .write(
            &h.admin,
            Method::POST,
            "/api/v1/projects/dev/enrollment-tokens",
            json!({"kind": "kubernetes", "target": {"type": "replace_source", "source_id": agent["source_id"]}}),
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);

    h.finish().await;
}

#[tokio::test]
async fn revoking_an_agent_keeps_its_cluster_and_notifies() {
    let h = harness!(Harness::start());
    let agent = h.enroll_new(&h.new_cluster_token().await).await;
    let agent_id = agent["agent_id"].as_str().unwrap();
    let mut listener = h.listener().await;
    let uri = format!("/api/v1/projects/prod/agents/{agent_id}/revoke");

    let revoked = h.write(&h.admin, Method::POST, &uri, Value::Null).await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.json);
    assert_eq!(revoked.json["status"], "revoked");
    assert_eq!(revoked.json["revocation_reason"], "revoked");
    assert_eq!(revoked.json["revoked_by"], json!(h.admin_id));

    let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("revocation notification")
        .unwrap();
    assert_eq!(notification.payload(), agent_id);

    let audit = h.audit().await;
    let (action, actor, audited_agent, details) = audit.last().unwrap();
    assert_eq!(action, "agent.revoke");
    assert_eq!(*actor, Some(h.admin_id));
    assert_eq!(
        audited_agent.map(|id| id.to_string()).as_deref(),
        Some(agent_id)
    );
    assert_eq!(details["reason"], "revoked");

    // Revocation deletes nothing.
    assert_eq!(h.count("clusters").await, 1);
    assert_eq!(h.count("sources").await, 1);
    assert_eq!(h.count("agents").await, 1);

    let again = h.write(&h.admin, Method::POST, &uri, Value::Null).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let unknown = format!("/api/v1/projects/prod/agents/{}/revoke", Uuid::from_u128(3));
    let response = h.write(&h.admin, Method::POST, &unknown, Value::Null).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);

    // The source takes a replacement agent through a new token.
    let token = h
        .replacement_token(agent["source_id"].as_str().unwrap())
        .await;
    let replacement = h.enroll_new(&token).await;
    assert_eq!(replacement["source_id"], agent["source_id"]);

    h.finish().await;
}

#[tokio::test]
async fn a_public_key_is_registered_only_once() {
    let h = harness!(Harness::start());
    let key = AgentKey::generate();
    let first = h.new_cluster_token().await;
    let response = h
        .enroll(&key.body(&first, h.installation_id, FINGERPRINT))
        .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let second = h.new_cluster_token().await;
    let response = h
        .enroll(&key.body(&second, h.installation_id, FINGERPRINT))
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{:?}", response.json);
    assert_eq!(h.failure_reasons().await, ["public_key_reused"]);
    // The refused attempt rolled back, so the token stays usable with a new key.
    assert_eq!(h.count("clusters").await, 1);
    h.enroll_new(&second).await;

    h.finish().await;
}

#[tokio::test]
async fn malformed_enrollments_are_refused_and_audited() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    let key = AgentKey::generate();
    let good = key.body(&token, h.installation_id, FINGERPRINT);

    let mut cases = Vec::new();
    let mut body = good.clone();
    body["protocol_versions"] = json!([2, 3]);
    cases.push((body, "unsupported_protocol"));
    let mut body = good.clone();
    body["cluster_fingerprint"] = json!("");
    cases.push((body, "invalid_request"));
    let mut body = good.clone();
    body["agent_version"] = json!("x".repeat(65));
    cases.push((body, "invalid_request"));
    let mut body = good.clone();
    body["public_key"] = json!("too-short");
    cases.push((body, "invalid_public_key"));
    let mut body = good.clone();
    // The identity point is a weak key.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    body["public_key"] = json!(URL_SAFE_NO_PAD.encode(identity));
    cases.push((body, "invalid_public_key"));
    let mut body = good.clone();
    body["kind"] = json!("docker");
    cases.push((body, "invalid_request"));

    let mut expected = Vec::new();
    for (body, reason) in cases {
        let response = h.enroll(&body).await;
        assert!(
            response.status.is_client_error(),
            "{body} {:?}",
            response.json
        );
        assert_ne!(response.status, StatusCode::CREATED);
        expected.push(reason);
    }
    assert_eq!(h.failure_reasons().await, expected);
    assert_eq!(h.count("agents").await, 0);
    h.enroll_new(&token).await;

    h.finish().await;
}

#[tokio::test]
async fn failed_attempts_are_rate_limited_per_client() {
    let h = harness!(Harness::start());
    let token = h.new_cluster_token().await;
    let mut body = AgentKey::generate().body(&token, h.installation_id, FINGERPRINT);
    body["token"] = json!("vn_enroll_wrong");

    for _ in 0..10 {
        let response = h.enroll_from(&body, "198.51.100.1:1000", None).await;
        response.assert_generic_failure();
    }
    let limited = h.enroll_from(&body, "198.51.100.1:2000", None).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.json["error"], "rate_limited");
    let retry_after: u64 = limited.headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=6).contains(&retry_after), "{retry_after}");
    // Refused before any work, and not audited, so a flood cannot fill the audit log.
    assert_eq!(h.failure_reasons().await.len(), 10);

    // A limited client is refused before its body is read: a body that never
    // finishes still gets an immediate 429 instead of holding the request open.
    let (_sender, pending_body) =
        http_body_util::Channel::<axum::body::Bytes, std::convert::Infallible>::new(1);
    let mut request = Request::post("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::new(pending_body))
        .unwrap();
    let peer: SocketAddr = "198.51.100.1:3000".parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let limited = tokio::time::timeout(Duration::from_secs(5), h.send(request))
        .await
        .expect("a limited client is answered without reading its body");
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    // Another client is unaffected, even with a valid token.
    let key = AgentKey::generate();
    let response = h
        .enroll_from(
            &key.body(&token, h.installation_id, FINGERPRINT),
            "198.51.100.2:1000",
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);

    h.finish().await;
}

#[tokio::test]
async fn client_addresses_resolve_through_trusted_proxies_only() {
    let h = harness!(Harness::start_with(vec!["10.0.0.0/8".parse().unwrap()]));

    // Through a trusted proxy, the forwarded client address is recorded.
    let token = h.new_cluster_token().await;
    let response = h
        .enroll_from(
            &AgentKey::generate().body(&token, h.installation_id, FINGERPRINT),
            "10.1.2.3:5000",
            Some("203.0.113.50, 10.9.9.9"),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);

    // From anyone else, the header is ignored.
    let token = h.new_cluster_token().await;
    let response = h
        .enroll_from(
            &AgentKey::generate().body(&token, h.installation_id, FINGERPRINT),
            "192.0.2.77:5000",
            Some("203.0.113.51"),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let addresses: Vec<String> =
        sqlx::query_scalar("SELECT host(source_address) FROM agents ORDER BY enrolled_at, id")
            .fetch_all(&h.db.pool)
            .await
            .unwrap();
    let mut addresses = addresses;
    addresses.sort();
    assert_eq!(addresses, ["192.0.2.77", "203.0.113.50"]);

    h.finish().await;
}
