//! Agent session and WebSocket connection tests against a real PostgreSQL database and
//! a real listening server.
//!
//! These tests need PostgreSQL. Set `DATABASE_URL` to a server where the user may create
//! databases (for example the Compose database, `postgres://vn:vn@localhost:5432/vn`).
//! Each test creates and drops its own database. Without `DATABASE_URL` the tests pass
//! after printing that they were skipped.
//!
//! Agents are enrolled through the enrollment endpoint with keys generated here, and the
//! WebSocket client is `tokio-tungstenite`, as in `vn-agent`.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;
use vn_server::{AgentConnectionSettings, AgentTasks, AppState, AuthService, router};

const ISSUER: &str = "https://id.example.com";
const PUBLIC_ORIGIN: &str = "https://vn.example.com";
const SESSION_COOKIE: &str = "__Host-vn_session";
const FINGERPRINT: &str = "6f1c2a8e-8a3b-4c55-9d1e-0b7c1f2e3d4a";
const CHALLENGE_KEY: [u8; 32] = [7; 32];
const SUBPROTOCOL: &str = "vn-agent.v1";

/// Connection timings short enough for tests. Revocation rechecks are slow by default,
/// so the revocation test shows the notification closes the connection.
fn fast_settings() -> AgentConnectionSettings {
    AgentConnectionSettings {
        heartbeat_interval: Duration::from_millis(200),
        idle_timeout: Duration::from_secs(3),
        recheck_interval: Duration::from_secs(60),
        hello_timeout: Duration::from_secs(3),
        max_message_bytes: 64 * 1024,
        ack_window: 16,
    }
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

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

        let mut url = url::Url::parse(&admin_url).expect("DATABASE_URL is a URL");
        url.set_path(&name);
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(url.as_str())
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
    tasks: Option<AgentTasks>,
    server: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
    http: reqwest::Client,
    installation_id: Uuid,
    admin: String,
}

impl Harness {
    async fn start() -> Option<Self> {
        Self::start_with(fast_settings(), true).await
    }

    async fn start_with(settings: AgentConnectionSettings, agents: bool) -> Option<Self> {
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
agents:
  challenge_key_env: VN_AGENT_CHALLENGE_KEY
"
        ))
        .unwrap();
        let auth = config.auth.unwrap();
        let secret = auth
            .resolve_client_secret_with(|_| Some("unused".into()))
            .unwrap();
        let mut state = AppState::new(db.pool.clone())
            .with_auth(AuthService::new(&auth, secret.as_ref()).unwrap())
            .with_agent_connection_settings(settings);
        if agents {
            let key = config
                .agents
                .unwrap()
                .resolve_challenge_key_with(|_| Some(STANDARD.encode(CHALLENGE_KEY)))
                .unwrap();
            state = state.with_agent_challenge_key(key);
        }
        let tasks = state.start_agent_tasks().await.unwrap();
        let app = router(state, None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let installation_id = sqlx::query_scalar("SELECT installation_id FROM installation")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        let mut h = Self {
            db,
            tasks: Some(tasks),
            server,
            addr,
            http: reqwest::Client::new(),
            installation_id,
            admin: String::new(),
        };
        h.admin = h.admin_session().await;
        let created = h
            .admin_post(
                "/api/v1/projects",
                json!({"slug": "prod", "name": "Production"}),
            )
            .await;
        assert_eq!(created.0, StatusCode::CREATED, "{:?}", created.1);
        Some(h)
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn admin_session(&self) -> String {
        let user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (issuer, subject) VALUES ($1, 'alice') RETURNING id",
        )
        .bind(ISSUER)
        .fetch_one(&self.db.pool)
        .await
        .unwrap();
        let token = random_hex(32);
        sqlx::query(
            "INSERT INTO sessions \
                 (token_hash, user_id, installation_admin, created_at, last_seen_at, expires_at) \
             VALUES ($1, $2, true, now(), now(), now() + interval '12 hours')",
        )
        .bind(Sha256::digest(token.as_bytes()).to_vec())
        .bind(user_id)
        .execute(&self.db.pool)
        .await
        .unwrap();
        token
    }

    async fn admin_post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .http
            .post(self.url(path))
            .header("cookie", format!("{SESSION_COOKIE}={}", self.admin))
            .header("origin", PUBLIC_ORIGIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        read(response).await
    }

    async fn post(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        let response = self
            .http
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .unwrap();
        read(response).await
    }

    /// Enrolls a new agent for a new cluster.
    async fn enroll(&self) -> TestAgent {
        let (status, created) = self
            .admin_post(
                "/api/v1/projects/prod/enrollment-tokens",
                json!({
                    "kind": "kubernetes",
                    "target": {"type": "new_cluster", "display_name": "east"},
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created:?}");
        let token = created["secret"].as_str().unwrap();
        let token_id = Uuid::try_parse(&token["vn_enroll_".len()..][..32]).unwrap();
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let key = SigningKey::from_bytes(&seed);
        let public_key = key.verifying_key().to_bytes();
        let message =
            vn_core::enrollment_signing_message(self.installation_id, token_id, &public_key);
        let (status, enrolled) = self
            .post(
                "/api/v1/agent/enroll",
                &json!({
                    "token": token,
                    "installation_id": self.installation_id,
                    "kind": "kubernetes",
                    "public_key": URL_SAFE_NO_PAD.encode(public_key),
                    "signature": URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()),
                    "agent_version": "0.1.0",
                    "protocol_versions": [1],
                    "cluster_fingerprint": FINGERPRINT,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{enrolled:?}");
        TestAgent {
            key,
            agent_id: uuid(&enrolled["agent_id"]),
            key_id: enrolled["key_id"].as_str().unwrap().to_owned(),
            source_id: uuid(&enrolled["source_id"]),
            installation_id: self.installation_id,
        }
    }

    async fn challenge(&self, agent_id: Uuid) -> Value {
        let (status, challenge) = self
            .post(
                "/api/v1/agent/auth/challenge",
                &json!({ "agent_id": agent_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{challenge:?}");
        challenge
    }

    /// Answers `challenge` as `agent` would.
    async fn answer(&self, agent: &TestAgent, challenge: &Value) -> (StatusCode, Value) {
        self.post("/api/v1/agent/auth/session", &agent.answer(challenge))
            .await
    }

    /// A fresh session token for `agent`.
    async fn session(&self, agent: &TestAgent) -> String {
        let challenge = self.challenge(agent.agent_id).await;
        let (status, session) = self.answer(agent, &challenge).await;
        assert_eq!(status, StatusCode::CREATED, "{session:?}");
        session["token"].as_str().unwrap().to_owned()
    }

    /// Opens a WebSocket connection with `token`.
    async fn connect(
        &self,
        token: &str,
    ) -> Result<(Ws, tungstenite::handshake::client::Response), tungstenite::Error> {
        let mut request = format!("ws://{}/api/v1/agent/connect", self.addr)
            .into_client_request()
            .unwrap();
        let headers = request.headers_mut();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers.insert(
            "sec-websocket-protocol",
            "vn-agent.v2, vn-agent.v1".parse().unwrap(),
        );
        tokio_tungstenite::connect_async(request).await
    }

    /// Connects, reads `welcome`, and sends `hello` with `fingerprint`.
    async fn connect_with_hello(&self, agent: &TestAgent, fingerprint: &str) -> (Ws, Value) {
        let token = self.session(agent).await;
        let (mut ws, response) = self.connect(&token).await.unwrap();
        assert_eq!(
            response.headers()["sec-websocket-protocol"],
            SUBPROTOCOL,
            "the server selects the highest common version"
        );
        let welcome = next_message(&mut ws).await;
        assert_eq!(welcome["type"], "welcome");
        assert_eq!(welcome["seq"], 1);
        send(&mut ws, &hello(1, fingerprint)).await;
        (ws, welcome)
    }

    async fn connection(&self, id: Uuid) -> ConnectionRow {
        sqlx::query_as(
            "SELECT agent_id, source_id, sync_epoch, closed_at, close_code, agent_version, \
                    kubernetes_version \
             FROM agent_connections WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.db.pool)
        .await
        .unwrap()
    }

    /// Waits for the server to record that connection `id` closed.
    async fn closed_connection(&self, id: Uuid) -> ConnectionRow {
        for _ in 0..100 {
            let row = self.connection(id).await;
            if row.closed_at.is_some() {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("connection {id} was not recorded as closed");
    }

    async fn audit_reasons(&self, action: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT details->>'reason' FROM audit_events WHERE action = $1 ORDER BY id",
        )
        .bind(action)
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

    async fn finish(mut self) {
        if let Some(tasks) = self.tasks.take() {
            tasks.shutdown(Duration::from_secs(5)).await;
        }
        self.server.abort();
        self.db.drop_database().await;
    }
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct ConnectionRow {
    agent_id: Uuid,
    source_id: Uuid,
    sync_epoch: i64,
    closed_at: Option<DateTime<Utc>>,
    close_code: Option<i32>,
    agent_version: String,
    kubernetes_version: Option<String>,
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn read(response: reqwest::Response) -> (StatusCode, Value) {
    let status = response.status();
    let json = response.json().await.unwrap_or(Value::Null);
    (status, json)
}

fn uuid(value: &Value) -> Uuid {
    Uuid::try_parse(value.as_str().unwrap()).unwrap()
}

struct TestAgent {
    key: SigningKey,
    agent_id: Uuid,
    key_id: String,
    source_id: Uuid,
    installation_id: Uuid,
}

impl TestAgent {
    fn sign(&self, challenge: &Value) -> String {
        let nonce: [u8; 32] = URL_SAFE_NO_PAD
            .decode(challenge["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let message = vn_core::session_signing_message(
            self.installation_id,
            self.agent_id,
            &self.key_id,
            uuid(&challenge["challenge_id"]),
            &nonce,
        );
        URL_SAFE_NO_PAD.encode(self.key.sign(&message).to_bytes())
    }

    fn answer(&self, challenge: &Value) -> Value {
        json!({
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "expires_at": challenge["expires_at"],
            "mac": challenge["mac"],
            "signature": self.sign(challenge),
        })
    }
}

/// A challenge with a chosen expiry, MAC'd with the test challenge key as the server
/// would.
fn forged_challenge(agent_id: Uuid, expires_at: i64) -> Value {
    let challenge_id = Uuid::from_u128(u128::from_be_bytes(rand_bytes()));
    let nonce: [u8; 32] = [rand_bytes::<16>(), rand_bytes::<16>()]
        .concat()
        .try_into()
        .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&CHALLENGE_KEY).unwrap();
    mac.update(b"vn-agent-challenge-v1\0");
    mac.update(agent_id.as_bytes());
    mac.update(challenge_id.as_bytes());
    mac.update(&nonce);
    mac.update(&expires_at.to_be_bytes());
    json!({
        "challenge_id": challenge_id,
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "expires_at": DateTime::from_timestamp(expires_at, 0).unwrap(),
        "mac": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
    })
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

fn hello(seq: u64, fingerprint: &str) -> Value {
    json!({
        "type": "hello",
        "seq": seq,
        "body": {
            "agent_version": "0.2.0",
            "capabilities": [],
            "cluster_fingerprint": fingerprint,
            "kubernetes_version": "v1.35.1",
        },
    })
}

async fn send(ws: &mut Ws, message: &Value) {
    ws.send(Message::text(message.to_string())).await.unwrap();
}

/// The next text message, skipping pings.
async fn next_message(ws: &mut Ws) -> Value {
    let read = async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => panic!("expected a text message, got {other:?}"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .expect("a message within 5 seconds")
}

/// Reads until the server's close frame and returns its code and reason.
async fn expect_close(ws: &mut Ws) -> (u16, String) {
    let read = async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(CloseFrame { code, reason })))) => {
                    return (u16::from(code), reason.to_string());
                }
                Some(Ok(Message::Close(None))) => panic!("close frame without a code"),
                Some(Ok(_)) => continue,
                other => panic!("expected a close frame, got {other:?}"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .expect("a close frame within 5 seconds")
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
// Sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_agent_trades_a_signed_challenge_for_a_session() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;

    let challenge = h.challenge(agent.agent_id).await;
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(challenge["nonce"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    let expires_at: DateTime<Utc> =
        serde_json::from_value(challenge["expires_at"].clone()).unwrap();
    let lifetime = expires_at - Utc::now();
    assert!(
        lifetime.num_seconds() > 50 && lifetime.num_seconds() <= 60,
        "{lifetime}"
    );
    // Issuing a challenge writes nothing.
    assert_eq!(h.count("consumed_agent_challenges").await, 0);

    let (status, session) = h.answer(&agent, &challenge).await;
    assert_eq!(status, StatusCode::CREATED, "{session:?}");
    let token = session["token"].as_str().unwrap();
    assert!(token.starts_with("vn_agent_session_"), "{token}");
    let expires_at: DateTime<Utc> = serde_json::from_value(session["expires_at"].clone()).unwrap();
    let lifetime = expires_at - Utc::now();
    assert!(
        lifetime.num_minutes() >= 14 && lifetime.num_minutes() <= 15,
        "{lifetime}"
    );

    // Only the token's hash is stored.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM agent_sessions")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(stored, Sha256::digest(token.as_bytes()).to_vec());
    assert_eq!(h.count("consumed_agent_challenges").await, 1);

    // Unknown agents get challenges too, so the endpoint does not reveal which exist.
    let unknown = h.challenge(Uuid::from_u128(42)).await;
    let impostor = TestAgent {
        agent_id: Uuid::from_u128(42),
        ..agent
    };
    let (status, body) = h.answer(&impostor, &unknown).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "session_failed");
    h.finish().await;
}

#[tokio::test]
async fn a_challenge_is_answered_only_once() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let challenge = h.challenge(agent.agent_id).await;
    let (status, _) = h.answer(&agent, &challenge).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = h.answer(&agent, &challenge).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body:?}");
    assert_eq!(body["error"], "challenge_used");
    assert_eq!(h.count("agent_sessions").await, 1);
    assert_eq!(
        h.audit_reasons("agent.session_failed").await,
        ["challenge_reused"]
    );
    h.finish().await;
}

#[tokio::test]
async fn a_bad_signature_or_altered_challenge_is_refused() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;

    // Signed with another key.
    let challenge = h.challenge(agent.agent_id).await;
    let other = TestAgent {
        key: SigningKey::from_bytes(&[9; 32]),
        ..h.enroll().await
    };
    let mut body = agent.answer(&challenge);
    body["signature"] = other
        .sign(&json!({
            "nonce": challenge["nonce"],
            "challenge_id": challenge["challenge_id"],
        }))
        .into();
    let (status, refused) = h.post("/api/v1/agent/auth/session", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused["error"], "session_failed");

    // A challenge issued for another agent fails the MAC check before any signature.
    let theirs = h.challenge(other.agent_id).await;
    let (status, refused) = h.answer(&agent, &theirs).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused["error"], "challenge_invalid");

    // An altered nonce breaks the MAC.
    let mut altered = challenge.clone();
    altered["nonce"] = URL_SAFE_NO_PAD.encode([0u8; 32]).into();
    let (status, refused) = h.answer(&agent, &altered).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused["error"], "challenge_invalid");

    // A key ID that is not the agent's.
    let mut body = agent.answer(&challenge);
    body["key_id"] = other.key_id.clone().into();
    let (status, refused) = h.post("/api/v1/agent/auth/session", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused["error"], "session_failed");

    // The failed attempts did not use the challenge.
    let (status, _) = h.answer(&agent, &challenge).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        h.audit_reasons("agent.session_failed").await,
        ["bad_signature", "unknown_key"]
    );
    h.finish().await;
}

#[tokio::test]
async fn an_expired_challenge_is_refused() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let now = Utc::now().timestamp();

    let expired = forged_challenge(agent.agent_id, now - 1);
    let (status, body) = h.answer(&agent, &expired).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body:?}");
    assert_eq!(body["error"], "challenge_expired");

    // A valid MAC with an expiry the server would never issue means a leaked key.
    let far = forged_challenge(agent.agent_id, now + 3600);
    let (status, body) = h.answer(&agent, &far).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body:?}");
    assert_eq!(body["error"], "challenge_invalid");

    // The forging works: a current expiry is accepted.
    let current = forged_challenge(agent.agent_id, now + 30);
    let (status, body) = h.answer(&agent, &current).await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    h.finish().await;
}

#[tokio::test]
async fn a_revoked_agent_gets_no_session_and_loses_its_sessions() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let token = h.session(&agent).await;
    let (status, _) = h
        .admin_post(
            &format!("/api/v1/projects/prod/agents/{}/revoke", agent.agent_id),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.count("agent_sessions").await, 0);

    let challenge = h.challenge(agent.agent_id).await;
    let (status, body) = h.answer(&agent, &challenge).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body:?}");
    assert_eq!(body["error"], "agent_revoked");
    assert_eq!(
        h.audit_reasons("agent.session_failed").await,
        ["agent_revoked"]
    );

    // The session issued before the revocation no longer opens connections.
    let Err(tungstenite::Error::Http(response)) = h.connect(&token).await else {
        panic!("connection with a revoked agent's session was accepted");
    };
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    h.finish().await;
}

#[tokio::test]
async fn without_a_challenge_key_agent_authentication_is_unavailable() {
    let h = harness!(Harness::start_with(fast_settings(), false));
    let agent = h.enroll().await;
    let (status, body) = h
        .post(
            "/api/v1/agent/auth/challenge",
            &json!({"agent_id": agent.agent_id}),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "agents_disabled");
    let (status, _) = h.post("/api/v1/agent/auth/session", &json!({})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let response = h
        .http
        .get(h.url("/api/v1/agent/connect"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    h.finish().await;
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failed_upgrades_answer_with_json_errors() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let token = h.session(&agent).await;

    // A plain request without an upgrade.
    let response = h
        .http
        .get(h.url("/api/v1/agent/connect"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error(), "{}", response.status());
    let (_, body) = read(response).await;
    assert_eq!(body["error"], "websocket_required");

    // No supported subprotocol.
    let mut request = format!("ws://{}/api/v1/agent/connect", h.addr)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
        .headers_mut()
        .insert("sec-websocket-protocol", "vn-agent.v9".parse().unwrap());
    let Err(tungstenite::Error::Http(response)) = tokio_tungstenite::connect_async(request).await
    else {
        panic!("upgrade without a supported subprotocol was accepted");
    };
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body().as_deref().unwrap()).unwrap();
    assert_eq!(body["error"], "unsupported_protocol");
    assert!(
        body["message"].as_str().unwrap().contains("vn-agent.v1"),
        "{body:?}"
    );

    // A wrong token.
    let Err(tungstenite::Error::Http(response)) = h.connect("vn_agent_session_nope").await else {
        panic!("upgrade with a bad token was accepted");
    };
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body().as_deref().unwrap()).unwrap();
    assert_eq!(body["error"], "session_invalid");
    assert_eq!(h.count("agent_connections").await, 0);
    h.finish().await;
}

#[tokio::test]
async fn a_connection_starts_with_welcome_and_hello() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    let body = &welcome["body"];
    assert_eq!(body["sync_epoch"], 1);
    assert_eq!(body["heartbeat_interval_seconds"], 1);
    assert_eq!(body["ack_window"], 16);
    assert_eq!(body["max_message_bytes"], 64 * 1024);
    assert_eq!(body["capabilities"], json!([]));
    let connection_id = uuid(&body["connection_id"]);

    // Unknown types are answered and the connection continues.
    send(
        &mut ws,
        &json!({"type": "from_the_future", "seq": 2, "body": {}}),
    )
    .await;
    let error = next_message(&mut ws).await;
    assert_eq!(error["type"], "error");
    assert_eq!(error["seq"], 2);
    assert_eq!(error["body"]["code"], "unsupported_type");
    assert_eq!(error["body"]["ref_seq"], 2);

    // The server pings, so the connection carries traffic.
    let ping = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Message::Ping(_))) = ws.next().await {
                return;
            }
        }
    })
    .await;
    assert!(ping.is_ok(), "no ping from the server");

    let row = h.connection(connection_id).await;
    assert_eq!(row.agent_id, agent.agent_id);
    assert_eq!(row.source_id, agent.source_id);
    assert_eq!(row.sync_epoch, 1);
    assert_eq!(row.closed_at, None);
    assert_eq!(row.agent_version, "0.2.0");
    assert_eq!(row.kubernetes_version.as_deref(), Some("v1.35.1"));
    let version: String = sqlx::query_scalar("SELECT agent_version FROM agents WHERE id = $1")
        .bind(agent.agent_id)
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(version, "0.2.0");

    ws.close(Some(CloseFrame {
        code: CloseCode::Normal,
        reason: "bye".into(),
    }))
    .await
    .unwrap();
    let row = h.closed_connection(connection_id).await;
    assert_eq!(row.close_code, Some(1000));

    // The next connection gets the next epoch of the source.
    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    assert_eq!(welcome["body"]["sync_epoch"], 2);
    ws.close(None).await.unwrap();
    h.finish().await;
}

#[tokio::test]
async fn a_sequence_gap_or_repeat_closes_with_a_protocol_error() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;

    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    send(&mut ws, &json!({"type": "status", "seq": 3, "body": {}})).await;
    let (code, reason) = expect_close(&mut ws).await;
    assert_eq!(code, 4000);
    assert!(reason.contains("expected seq 2, got 3"), "{reason}");
    let row = h
        .closed_connection(uuid(&welcome["body"]["connection_id"]))
        .await;
    assert_eq!(row.close_code, Some(4000));

    let (mut ws, _) = h.connect_with_hello(&agent, FINGERPRINT).await;
    send(&mut ws, &hello(1, FINGERPRINT)).await;
    let (code, _) = expect_close(&mut ws).await;
    assert_eq!(code, 4000);

    // The first message must be `hello`.
    let token = h.session(&agent).await;
    let (mut ws, _) = h.connect(&token).await.unwrap();
    next_message(&mut ws).await;
    send(&mut ws, &json!({"type": "status", "seq": 1, "body": {}})).await;
    let (code, reason) = expect_close(&mut ws).await;
    assert_eq!(code, 4000);
    assert!(reason.contains("hello"), "{reason}");
    h.finish().await;
}

#[tokio::test]
async fn a_different_cluster_fingerprint_closes_with_identity_mismatch() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let (mut ws, welcome) = h.connect_with_hello(&agent, "another-cluster").await;
    let (code, _) = expect_close(&mut ws).await;
    assert_eq!(code, 4010);
    let row = h
        .closed_connection(uuid(&welcome["body"]["connection_id"]))
        .await;
    assert_eq!(row.close_code, Some(4010));
    assert_eq!(
        h.audit_reasons("agent.connect_refused").await,
        ["fingerprint_mismatch"]
    );
    h.finish().await;
}

#[tokio::test]
async fn a_newer_connection_supersedes_the_older_one() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let (mut old, old_welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    let (mut new, new_welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    assert_eq!(new_welcome["body"]["sync_epoch"], 2);

    let (code, _) = expect_close(&mut old).await;
    assert_eq!(code, 4009);
    let old_row = h
        .closed_connection(uuid(&old_welcome["body"]["connection_id"]))
        .await;
    assert_eq!(old_row.close_code, Some(4009));
    let new_row = h
        .connection(uuid(&new_welcome["body"]["connection_id"]))
        .await;
    assert_eq!(new_row.closed_at, None);

    // The newer connection keeps working.
    send(&mut new, &json!({"type": "later", "seq": 2, "body": {}})).await;
    assert_eq!(next_message(&mut new).await["body"]["ref_seq"], 2);
    new.close(None).await.unwrap();
    h.finish().await;
}

#[tokio::test]
async fn revoking_an_agent_closes_its_open_connection() {
    let h = harness!(Harness::start());
    let agent = h.enroll().await;
    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    // Wait until `hello` is processed, so the close comes from the revocation.
    send(&mut ws, &json!({"type": "later", "seq": 2, "body": {}})).await;
    next_message(&mut ws).await;

    let (status, _) = h
        .admin_post(
            &format!("/api/v1/projects/prod/agents/{}/revoke", agent.agent_id),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // The recheck interval is a minute, so only the notification can close it this fast.
    let (code, _) = expect_close(&mut ws).await;
    assert_eq!(code, 4003);
    let row = h
        .closed_connection(uuid(&welcome["body"]["connection_id"]))
        .await;
    assert_eq!(row.close_code, Some(4003));
    h.finish().await;
}

#[tokio::test]
async fn the_periodic_recheck_closes_a_revoked_agent_without_a_notification() {
    let settings = AgentConnectionSettings {
        recheck_interval: Duration::from_millis(300),
        ..fast_settings()
    };
    let h = harness!(Harness::start_with(settings, true));
    let agent = h.enroll().await;
    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    sqlx::query(
        "UPDATE agents SET revoked_at = now(), revocation_reason = 'revoked' WHERE id = $1",
    )
    .bind(agent.agent_id)
    .execute(&h.db.pool)
    .await
    .unwrap();
    let (code, _) = expect_close(&mut ws).await;
    assert_eq!(code, 4003);

    // The recheck also records the last-seen time.
    let row = h
        .closed_connection(uuid(&welcome["body"]["connection_id"]))
        .await;
    assert_eq!(row.close_code, Some(4003));
    h.finish().await;
}

#[tokio::test]
async fn silence_and_oversized_messages_close_the_connection() {
    let settings = AgentConnectionSettings {
        idle_timeout: Duration::from_millis(800),
        hello_timeout: Duration::from_millis(500),
        max_message_bytes: 4096,
        ..fast_settings()
    };
    let h = harness!(Harness::start_with(settings, true));
    let agent = h.enroll().await;

    // No `hello` in time.
    let token = h.session(&agent).await;
    let (mut ws, _) = h.connect(&token).await.unwrap();
    let (code, reason) = expect_close(&mut ws).await;
    assert_eq!(code, 4000);
    assert!(reason.contains("hello"), "{reason}");

    // No traffic at all: the client does not read, so it never answers pings.
    let (mut ws, _) = h.connect_with_hello(&agent, FINGERPRINT).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (code, reason) = expect_close(&mut ws).await;
    assert_eq!(code, 4000);
    assert!(reason.contains("heartbeat"), "{reason}");

    // A message over the announced limit.
    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    assert_eq!(welcome["body"]["max_message_bytes"], 4096);
    let padding = "x".repeat(8192);
    send(
        &mut ws,
        &json!({"type": "later", "seq": 2, "body": {"padding": padding}}),
    )
    .await;
    let (code, _) = expect_close(&mut ws).await;
    assert_eq!(code, 1009);
    let row = h
        .closed_connection(uuid(&welcome["body"]["connection_id"]))
        .await;
    assert_eq!(row.close_code, Some(1009));
    h.finish().await;
}

#[tokio::test]
async fn shutdown_and_startup_close_open_connections() {
    let mut h = harness!(Harness::start());
    let agent = h.enroll().await;
    let (mut ws, welcome) = h.connect_with_hello(&agent, FINGERPRINT).await;
    let connection_id = uuid(&welcome["body"]["connection_id"]);

    // Stopping the server closes open connections with 1001 (going away).
    h.tasks
        .take()
        .unwrap()
        .shutdown(Duration::from_secs(5))
        .await;
    let (code, _) = expect_close(&mut ws).await;
    assert_eq!(code, 1001);
    assert_eq!(h.connection(connection_id).await.close_code, Some(1001));

    // A row left open by a server that stopped without recording it is closed at the
    // next startup, without a close code.
    let stale = Uuid::from_u128(7);
    sqlx::query(
        "INSERT INTO agent_connections (id, agent_id, source_id, sync_epoch, agent_version) \
         VALUES ($1, $2, $3, 99, '0.1.0')",
    )
    .bind(stale)
    .bind(agent.agent_id)
    .bind(agent.source_id)
    .execute(&h.db.pool)
    .await
    .unwrap();
    h.tasks = Some(
        AppState::new(h.db.pool.clone())
            .start_agent_tasks()
            .await
            .unwrap(),
    );
    let row = h.connection(stale).await;
    assert!(row.closed_at.is_some());
    assert_eq!(row.close_code, None);
    h.finish().await;
}

#[tokio::test]
async fn the_revocation_listener_leaves_a_single_connection_pool_usable() {
    let Some(db) = TestDb::create().await else {
        return;
    };
    let small = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with((*db.pool.connect_options()).clone())
        .await
        .unwrap();
    let tasks = AppState::new(small.clone())
        .start_agent_tasks()
        .await
        .unwrap();
    // The listener keeps its connection for as long as the server runs. Requests must
    // still get the application pool's only connection.
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&small)
        .await
        .expect("the application pool still has a connection");
    assert_eq!(one, 1);
    tasks.shutdown(Duration::from_secs(1)).await;
    small.close().await;
    db.drop_database().await;
}
