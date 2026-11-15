//! The agent's enrollment and connection loop against a real `vn-server` and
//! PostgreSQL. Only the Kubernetes facts are supplied by the test.
//!
//! These tests need PostgreSQL. Set `DATABASE_URL` to a server where the user may create
//! databases. Each test creates and drops its own database. Without `DATABASE_URL` the
//! tests pass after printing that they were skipped.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use tokio::sync::watch;
use uuid::Uuid;
use vn_agent::backoff::Backoff;
use vn_agent::client::ServerClient;
use vn_agent::cluster::ClusterInfo;
use vn_agent::identity::{Identity, IdentityStore};
use vn_agent::runner::{Runner, Stop};
use vn_server::{AgentConnectionSettings, AgentTasks, AppState, AuthService, router};

const ISSUER: &str = "https://id.example.com";
const PUBLIC_ORIGIN: &str = "https://vn.example.com";
const FINGERPRINT: &str = "0d7a6c55-3f0e-4b8e-9a51-2f6c1e9b7d10";

struct Harness {
    pool: PgPool,
    admin_url: String,
    name: String,
    tasks: Option<AgentTasks>,
    server: tokio::task::JoinHandle<()>,
    base: String,
    admin: String,
    http: reqwest::Client,
}

impl Harness {
    async fn start(settings: AgentConnectionSettings) -> Option<Self> {
        let Ok(admin_url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL is not set");
            return None;
        };
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        let name = format!(
            "vn_test_{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let mut admin = PgConnection::connect(&admin_url).await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        admin.close().await.ok();
        let mut url = url::Url::parse(&admin_url).unwrap();
        url.set_path(&name);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(url.as_str())
            .await
            .unwrap();
        vn_server::MIGRATOR.run(&pool).await.unwrap();

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
agents: {{challenge_key_env: VN_AGENT_CHALLENGE_KEY}}
"
        ))
        .unwrap();
        let auth = config.auth.unwrap();
        let secret = auth
            .resolve_client_secret_with(|_| Some("unused".into()))
            .unwrap();
        let key = config
            .agents
            .unwrap()
            .resolve_challenge_key_with(|_| Some(STANDARD.encode([3u8; 32])))
            .unwrap();
        let state = AppState::new(pool.clone())
            .with_auth(AuthService::new(&auth, secret.as_ref()).unwrap())
            .with_agent_challenge_key(key)
            .with_agent_connection_settings(settings);
        let tasks = state.start_agent_tasks().await.unwrap();
        let app = router(state, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (issuer, subject) VALUES ($1, 'alice') RETURNING id",
        )
        .bind(ISSUER)
        .fetch_one(&pool)
        .await
        .unwrap();
        let admin = format!("{:x}", u128::from_le_bytes([9; 16]));
        sqlx::query(
            "INSERT INTO sessions \
                 (token_hash, user_id, installation_admin, created_at, last_seen_at, expires_at) \
             VALUES ($1, $2, true, now(), now(), now() + interval '1 hour')",
        )
        .bind(Sha256::digest(admin.as_bytes()).to_vec())
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        let h = Self {
            pool,
            admin_url,
            name,
            tasks: Some(tasks),
            server,
            base: format!("http://{addr}"),
            admin,
            http: reqwest::Client::new(),
        };
        h.admin_post("/api/v1/projects", json!({"slug": "prod", "name": "Prod"}))
            .await;
        Some(h)
    }

    async fn admin_post(&self, path: &str, body: serde_json::Value) -> serde_json::Value {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .header("cookie", format!("__Host-vn_session={}", self.admin))
            .header("origin", PUBLIC_ORIGIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{}", response.status());
        response.json().await.unwrap()
    }

    /// Enrolls like a fresh agent and stores the identity in a file in `dir`.
    async fn enroll(&self, dir: &tempfile::TempDir) -> Identity {
        let created = self
            .admin_post(
                "/api/v1/projects/prod/enrollment-tokens",
                json!({"kind": "kubernetes", "target": {"type": "new_cluster", "display_name": "east"}}),
            )
            .await;
        let token = created["secret"].as_str().unwrap();
        let key = vn_agent::enroll::generate_key().unwrap();
        let identity = vn_agent::enroll::enroll(&self.client(), token, &key, FINGERPRINT)
            .await
            .unwrap();
        // A retry with the same key, as after a lost response, gets the same identity.
        let repeated = vn_agent::enroll::enroll(&self.client(), token, &key, FINGERPRINT)
            .await
            .unwrap();
        assert_eq!(repeated.agent_id, identity.agent_id);
        assert_eq!(repeated.key_id, identity.key_id);
        let store = IdentityStore::File(dir.path().join("identity.json"));
        store.create(&identity).await.unwrap();
        store.load().await.unwrap().unwrap()
    }

    fn client(&self) -> ServerClient {
        ServerClient::new(&self.base).unwrap()
    }

    fn runner(&self, identity: Identity, fingerprint: &str) -> Runner {
        let cluster = ClusterInfo {
            fingerprint: fingerprint.to_owned(),
            kubernetes_version: Some("v1.35.2".into()),
        };
        Runner::new(self.client(), identity, cluster)
            .unwrap()
            .with_backoff(Backoff::new(
                Duration::from_millis(50),
                Duration::from_millis(200),
            ))
    }

    /// Waits for an open connection of `agent_id` with at least `epoch`, after `hello`.
    async fn open_connection(&self, agent_id: Uuid, epoch: i64) -> (Uuid, i64) {
        for _ in 0..200 {
            let row: Option<(Uuid, i64)> = sqlx::query_as(
                "SELECT id, sync_epoch FROM agent_connections \
                 WHERE agent_id = $1 AND closed_at IS NULL AND sync_epoch >= $2 \
                   AND kubernetes_version IS NOT NULL",
            )
            .bind(agent_id)
            .bind(epoch)
            .fetch_optional(&self.pool)
            .await
            .unwrap();
            if let Some(row) = row {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("agent {agent_id} did not connect");
    }

    async fn close_code(&self, connection_id: Uuid) -> Option<i32> {
        for _ in 0..200 {
            let row: (Option<i32>, bool) = sqlx::query_as(
                "SELECT close_code, closed_at IS NOT NULL FROM agent_connections WHERE id = $1",
            )
            .bind(connection_id)
            .fetch_one(&self.pool)
            .await
            .unwrap();
            if row.1 {
                return row.0;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("connection {connection_id} did not close");
    }

    async fn finish(mut self) {
        if let Some(tasks) = self.tasks.take() {
            tasks.shutdown(Duration::from_secs(5)).await;
        }
        self.server.abort();
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

fn fast() -> AgentConnectionSettings {
    AgentConnectionSettings {
        heartbeat_interval: Duration::from_millis(200),
        idle_timeout: Duration::from_secs(3),
        recheck_interval: Duration::from_millis(300),
        hello_timeout: Duration::from_secs(3),
        ..AgentConnectionSettings::default()
    }
}

macro_rules! harness {
    ($expr:expr) => {
        match $expr.await {
            Some(h) => h,
            None => return,
        }
    };
}

async fn stopped(run: tokio::task::JoinHandle<Stop>) -> Stop {
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the agent stops within 10 seconds")
        .unwrap()
}

#[tokio::test]
async fn the_agent_enrolls_connects_reconnects_and_stops_when_revoked() {
    let h = harness!(Harness::start(fast()));
    let dir = tempfile::tempdir().unwrap();
    let identity = h.enroll(&dir).await;
    let agent_id = identity.agent_id;
    let (_stop_tx, stop) = watch::channel(false);
    let run = tokio::spawn(h.runner(identity, FINGERPRINT).run(stop));

    let (first, epoch) = h.open_connection(agent_id, 1).await;
    assert_eq!(epoch, 1);
    // Heartbeats keep the connection up past the server's idle timeout.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let (still, _) = h.open_connection(agent_id, 1).await;
    assert_eq!(still, first);

    // The server closes the connection (as for a superseded one); the agent reconnects
    // and gets the next epoch.
    sqlx::query("UPDATE agent_connections SET closed_at = now(), close_code = 4009 WHERE id = $1")
        .bind(first)
        .execute(&h.pool)
        .await
        .unwrap();
    let (second, epoch) = h.open_connection(agent_id, 2).await;
    assert_ne!(second, first);
    assert_eq!(epoch, 2);

    h.admin_post(
        &format!("/api/v1/projects/prod/agents/{agent_id}/revoke"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(stopped(run).await, Stop::Revoked);
    assert_eq!(h.close_code(second).await, Some(4003));
    h.finish().await;
}

#[tokio::test]
async fn the_agent_stops_on_an_identity_mismatch() {
    let h = harness!(Harness::start(fast()));
    let dir = tempfile::tempdir().unwrap();
    let identity = h.enroll(&dir).await;
    let (_stop_tx, stop) = watch::channel(false);
    let run = tokio::spawn(h.runner(identity, "a-different-cluster").run(stop));
    let Stop::IdentityMismatch(reason) = stopped(run).await else {
        panic!("expected an identity mismatch");
    };
    assert!(reason.contains("fingerprint"), "{reason}");
    h.finish().await;
}

#[tokio::test]
async fn the_agent_closes_cleanly_on_shutdown() {
    let h = harness!(Harness::start(fast()));
    let dir = tempfile::tempdir().unwrap();
    let identity = h.enroll(&dir).await;
    let agent_id = identity.agent_id;
    let (stop_tx, stop) = watch::channel(false);
    let run = tokio::spawn(h.runner(identity, FINGERPRINT).run(stop));
    let (connection, _) = h.open_connection(agent_id, 1).await;
    stop_tx.send(true).unwrap();
    assert_eq!(stopped(run).await, Stop::Shutdown);
    assert_eq!(h.close_code(connection).await, Some(1000));
    h.finish().await;
}
