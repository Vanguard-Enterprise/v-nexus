//! Inventory ingest and the inventory API, against a real PostgreSQL database and a real
//! listening server. The agent side is driven message by message over a WebSocket, so
//! each synchronization rule of `docs/agent-protocol.md` can be exercised directly.
//!
//! These tests need PostgreSQL. Set `DATABASE_URL` to a server where the user may create
//! databases. Each test creates and drops its own database. Without `DATABASE_URL` the
//! tests pass after printing that they were skipped.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;
use vn_server::{AgentConnectionSettings, AgentTasks, AppState, AuthService, router};

const ISSUER: &str = "https://id.example.com";
const PUBLIC_ORIGIN: &str = "https://vn.example.com";
const SESSION_COOKIE: &str = "__Host-vn_session";
const FINGERPRINT: &str = "4b0c7e1a-2d3f-4a5b-8c6d-7e8f9a0b1c2d";
const CHALLENGE_KEY: [u8; 32] = [5; 32];

fn settings() -> AgentConnectionSettings {
    AgentConnectionSettings {
        heartbeat_interval: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(10),
        recheck_interval: Duration::from_secs(60),
        hello_timeout: Duration::from_secs(5),
        max_message_bytes: 64 * 1024,
        ack_window: 64,
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Server {
    tasks: Option<AgentTasks>,
    handle: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
}

impl Server {
    async fn start(pool: &PgPool) -> Self {
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
            .resolve_challenge_key_with(|_| Some(STANDARD.encode(CHALLENGE_KEY)))
            .unwrap();
        let state = AppState::new(pool.clone())
            .with_auth(AuthService::new(&auth, &secret).unwrap())
            .with_agent_challenge_key(key)
            .with_agent_connection_settings(settings());
        let tasks = state.start_agent_tasks().await.unwrap();
        let app = router(state, None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            tasks: Some(tasks),
            handle,
            addr,
        }
    }

    async fn stop(mut self) {
        if let Some(tasks) = self.tasks.take() {
            tasks.shutdown(Duration::from_secs(5)).await;
        }
        self.handle.abort();
        let _ = self.handle.await;
    }
}

struct Harness {
    pool: PgPool,
    admin_url: String,
    name: String,
    server: Option<Server>,
    http: reqwest::Client,
    installation_id: Uuid,
    admin: String,
}

impl Harness {
    async fn start() -> Option<Self> {
        let Ok(admin_url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL is not set");
            return None;
        };
        let name = format!("vn_test_{}", random_hex(8));
        let mut admin = PgConnection::connect(&admin_url).await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        admin.close().await.ok();
        let mut url = url::Url::parse(&admin_url).unwrap();
        url.set_path(&name);
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(url.as_str())
            .await
            .unwrap();
        vn_server::MIGRATOR.run(&pool).await.unwrap();
        let server = Server::start(&pool).await;
        let installation_id = sqlx::query_scalar("SELECT installation_id FROM installation")
            .fetch_one(&pool)
            .await
            .unwrap();
        let mut h = Self {
            pool,
            admin_url,
            name,
            server: Some(server),
            http: reqwest::Client::new(),
            installation_id,
            admin: String::new(),
        };
        h.admin = h.user_session("alice", true).await;
        for (slug, name) in [("prod", "Production"), ("other", "Other")] {
            let (status, body) = h
                .post(
                    &h.admin.clone(),
                    "/api/v1/projects",
                    json!({"slug": slug, "name": name}),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body:?}");
        }
        Some(h)
    }

    fn addr(&self) -> SocketAddr {
        self.server.as_ref().unwrap().addr
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr())
    }

    /// Stops the server and starts a new one, with new state, on the same database.
    async fn restart(&mut self) {
        self.server.take().unwrap().stop().await;
        self.server = Some(Server::start(&self.pool).await);
    }

    /// A browser session for a new user `subject`.
    async fn user_session(&self, subject: &str, installation_admin: bool) -> String {
        let user_id: Uuid =
            sqlx::query_scalar("INSERT INTO users (issuer, subject) VALUES ($1, $2) RETURNING id")
                .bind(ISSUER)
                .bind(subject)
                .fetch_one(&self.pool)
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
        .bind(installation_admin)
        .execute(&self.pool)
        .await
        .unwrap();
        token
    }

    /// A session for a user with `role` in project `slug`.
    async fn member_session(&self, subject: &str, slug: &str, role: &str) -> String {
        let token = self.user_session(subject, false).await;
        sqlx::query(
            "INSERT INTO project_role_assignments (project_id, user_id, role) \
             SELECT p.id, u.id, $3 FROM projects p, users u WHERE p.slug = $1 AND u.subject = $2",
        )
        .bind(slug)
        .bind(subject)
        .bind(role)
        .execute(&self.pool)
        .await
        .unwrap();
        token
    }

    async fn post(&self, session: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .http
            .post(self.url(path))
            .header("cookie", format!("{SESSION_COOKIE}={session}"))
            .header("origin", PUBLIC_ORIGIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        read(response).await
    }

    async fn get_as(&self, session: Option<&str>, path: &str) -> (StatusCode, Value) {
        let mut request = self.http.get(self.url(path));
        if let Some(session) = session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
        }
        read(request.send().await.unwrap()).await
    }

    /// `GET path` as the installation admin, expecting 200.
    async fn get(&self, path: &str) -> Value {
        let (status, body) = self.get_as(Some(&self.admin), path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}: {body:?}");
        body
    }

    /// Enrolls a new agent for a new cluster `display_name` in project `slug`.
    async fn enroll(&self, slug: &str, display_name: &str) -> TestAgent {
        let (status, created) = self
            .post(
                &self.admin,
                &format!("/api/v1/projects/{slug}/enrollment-tokens"),
                json!({
                    "kind": "kubernetes",
                    "target": {"type": "new_cluster", "display_name": display_name},
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
        let response = self
            .http
            .post(self.url("/api/v1/agent/enroll"))
            .json(&json!({
                "token": token,
                "installation_id": self.installation_id,
                "kind": "kubernetes",
                "public_key": URL_SAFE_NO_PAD.encode(public_key),
                "signature": URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()),
                "agent_version": "0.1.0",
                "protocol_versions": [1],
                "cluster_fingerprint": FINGERPRINT,
            }))
            .send()
            .await
            .unwrap();
        let (status, enrolled) = read(response).await;
        assert_eq!(status, StatusCode::CREATED, "{enrolled:?}");
        TestAgent {
            key,
            agent_id: uuid(&enrolled["agent_id"]),
            key_id: enrolled["key_id"].as_str().unwrap().to_owned(),
            cluster_id: uuid(&enrolled["cluster_id"]),
            source_id: uuid(&enrolled["source_id"]),
            installation_id: self.installation_id,
        }
    }

    /// Opens a connection for `agent` and sends `hello` reporting `kubernetes_version`.
    async fn connect(&self, agent: &TestAgent, kubernetes_version: &str) -> AgentConn {
        let response = self
            .http
            .post(self.url("/api/v1/agent/auth/challenge"))
            .json(&json!({ "agent_id": agent.agent_id }))
            .send()
            .await
            .unwrap();
        let (status, challenge) = read(response).await;
        assert_eq!(status, StatusCode::OK, "{challenge:?}");
        let response = self
            .http
            .post(self.url("/api/v1/agent/auth/session"))
            .json(&agent.answer(&challenge))
            .send()
            .await
            .unwrap();
        let (status, session) = read(response).await;
        assert_eq!(status, StatusCode::CREATED, "{session:?}");
        let token = session["token"].as_str().unwrap();
        let mut request = format!("ws://{}/api/v1/agent/connect", self.addr())
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "vn-agent.v1".parse().unwrap());
        let (ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        let mut conn = AgentConn {
            ws,
            next_seq: 1,
            notices: Vec::new(),
            welcome: Value::Null,
        };
        conn.welcome = conn.next().await;
        assert_eq!(conn.welcome["type"], "welcome");
        conn.send(
            "hello",
            json!({
                "agent_version": "0.1.0",
                "capabilities": [],
                "cluster_fingerprint": FINGERPRINT,
                "kubernetes_version": kubernetes_version,
            }),
        )
        .await;
        // `hello` is recorded before inventory messages are dispatched.
        conn
    }

    async fn resources(&self, cluster_id: Uuid, query: &str) -> Vec<Value> {
        let body = self
            .get(&format!(
                "/api/v1/projects/prod/clusters/{cluster_id}/resources?{query}"
            ))
            .await;
        body["resources"].as_array().unwrap().clone()
    }

    /// `(name, state)` of the cluster's resources, including deleted ones.
    async fn names(&self, cluster_id: Uuid, collection: &str) -> Vec<(String, String)> {
        self.resources(
            cluster_id,
            &format!("collection={collection}&include_deleted=true&limit=500"),
        )
        .await
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_owned(),
                r["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
    }

    async fn cluster(&self, cluster_id: Uuid) -> Value {
        self.get(&format!("/api/v1/projects/prod/clusters/{cluster_id}"))
            .await
    }

    async fn rows(&self, cluster_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM inventory_resources WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn finish(mut self) {
        if let Some(server) = self.server.take() {
            server.stop().await;
        }
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

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One agent connection, driven by the test.
struct AgentConn {
    ws: Ws,
    next_seq: u64,
    /// `error` messages the server sent.
    notices: Vec<Value>,
    welcome: Value,
}

impl AgentConn {
    async fn send(&mut self, kind: &str, body: Value) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        let text = json!({"type": kind, "seq": seq, "body": body}).to_string();
        self.ws.send(Message::text(text)).await.unwrap();
        seq
    }

    async fn next(&mut self) -> Value {
        let read = async {
            loop {
                match self.ws.next().await {
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

    /// Waits until everything sent so far is acknowledged.
    async fn sync(&mut self) {
        let last = self.next_seq - 1;
        loop {
            let message = self.next().await;
            match message["type"].as_str() {
                Some("ack") if message["body"]["seq"].as_u64().unwrap() >= last => return,
                Some("ack") => continue,
                Some("error") => self.notices.push(message["body"].clone()),
                other => panic!("unexpected message {other:?}"),
            }
        }
    }

    /// Reads until the server's close frame and returns its code. Nothing is
    /// acknowledged before it.
    async fn expect_close(&mut self) -> u16 {
        let read = async {
            loop {
                match self.ws.next().await {
                    Some(Ok(Message::Close(Some(CloseFrame { code, .. })))) => {
                        return u16::from(code);
                    }
                    Some(Ok(Message::Text(text))) => {
                        let message: Value = serde_json::from_str(&text).unwrap();
                        assert_ne!(message["type"], "ack", "nothing is acknowledged");
                    }
                    Some(Ok(_)) => continue,
                    other => panic!("expected a close frame, got {other:?}"),
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .expect("a close frame within 5 seconds")
    }

    async fn close(mut self) {
        self.ws.close(None).await.ok();
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(Duration::from_secs(2), self.ws.next()).await
        {}
    }

    async fn snapshot_start(&mut self, collection: &str) -> Uuid {
        let id = Uuid::from_bytes(rand_bytes());
        self.send(
            "snapshot_start",
            json!({"snapshot_id": id, "collection": collection, "scope": {"namespace": null}}),
        )
        .await;
        id
    }

    async fn upsert(&mut self, snapshot: Option<Uuid>, object: &Value) -> u64 {
        let mut body = observation(object);
        body["object"] = object.clone();
        if let Some(id) = snapshot {
            body["snapshot_id"] = json!(id);
        }
        self.send("upsert", body).await
    }

    async fn delete(&mut self, object: &Value) -> u64 {
        self.send("delete", observation(object)).await
    }

    async fn snapshot_end(&mut self, id: Uuid, item_count: u64) {
        self.send(
            "snapshot_end",
            json!({"snapshot_id": id, "item_count": item_count, "resource_version": "999"}),
        )
        .await;
    }

    /// A complete snapshot of `objects`, acknowledged.
    async fn snapshot(&mut self, collection: &str, objects: &[Value]) {
        let id = self.snapshot_start(collection).await;
        for object in objects {
            self.upsert(Some(id), object).await;
        }
        self.snapshot_end(id, objects.len() as u64).await;
        self.sync().await;
    }
}

/// The observation fields of an object built by [`node`] or [`deployment`].
fn observation(object: &Value) -> Value {
    let collection = match object["kind"].as_str().unwrap() {
        "Node" => "v1/nodes",
        "Namespace" => "v1/namespaces",
        "Deployment" => "apps/v1/deployments",
        "StatefulSet" => "apps/v1/statefulsets",
        "DaemonSet" => "apps/v1/daemonsets",
        other => panic!("unknown kind {other}"),
    };
    let metadata = &object["metadata"];
    json!({
        "collection": collection,
        "uid": metadata["uid"],
        "namespace": metadata.get("namespace").cloned().unwrap_or(Value::Null),
        "name": metadata["name"],
        "resource_version": metadata["resourceVersion"],
        "observed_at": "2026-11-15T12:00:00Z",
    })
}

fn node(name: &str, uid: &str, rv: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {
            "name": name,
            "uid": uid,
            "resourceVersion": rv,
            "labels": {"node-role.kubernetes.io/control-plane": ""},
            "managedFields": [{"manager": "kubelet"}],
        },
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "nodeInfo": {"kubeletVersion": "v1.37.0", "osImage": "Debian GNU/Linux 12"},
            "addresses": [{"type": "InternalIP", "address": "172.18.0.2"}],
            "capacity": {"cpu": "4", "memory": "8Gi"},
            "images": [{"names": ["registry.k8s.io/pause:3.10"]}],
        },
    })
}

fn deployment(namespace: &str, name: &str, uid: &str, rv: &str) -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": rv},
        "spec": {"replicas": 2, "template": {"spec": {"containers": [{
            "name": "app",
            "image": format!("example/{name}:1"),
            "env": [{"name": "PASSWORD", "value": "hunter2"}],
        }]}}},
        "status": {"readyReplicas": 1},
    })
}

struct TestAgent {
    key: SigningKey,
    agent_id: Uuid,
    key_id: String,
    cluster_id: Uuid,
    source_id: Uuid,
    installation_id: Uuid,
}

impl TestAgent {
    fn answer(&self, challenge: &Value) -> Value {
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
        json!({
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "expires_at": challenge["expires_at"],
            "mac": challenge["mac"],
            "signature": URL_SAFE_NO_PAD.encode(self.key.sign(&message).to_bytes()),
        })
    }
}

async fn read(response: reqwest::Response) -> (StatusCode, Value) {
    let status = response.status();
    let json = response.json().await.unwrap_or(Value::Null);
    (status, json)
}

fn time(value: &Value) -> chrono::DateTime<chrono::Utc> {
    value.as_str().unwrap().parse().unwrap()
}

fn uuid(value: &Value) -> Uuid {
    Uuid::try_parse(value.as_str().unwrap()).unwrap()
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).unwrap();
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect()
}

macro_rules! harness {
    () => {
        match Harness::start().await {
            Some(h) => h,
            None => return,
        }
    };
}

/// Waits for the server to record that the agent's open connection closed.
async fn wait_disconnected(h: &Harness, agent: &TestAgent) {
    for _ in 0..100 {
        let open: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM agent_connections WHERE agent_id = $1 AND closed_at IS NULL",
        )
        .bind(agent.agent_id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
        if open == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the connection was not recorded as closed");
}

// ---------------------------------------------------------------------------
// Snapshots and deletions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_completed_snapshot_infers_deletions_of_resources_it_did_not_list() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot(
        "v1/nodes",
        &[
            node("a", "ua", "1"),
            node("b", "ub", "1"),
            node("c", "uc", "1"),
        ],
    )
    .await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present"), ("b", "present"), ("c", "present")])
    );

    // `a` is listed unchanged; `c` is missing.
    conn.snapshot("v1/nodes", &[node("a", "ua", "1"), node("b", "ub", "2")])
        .await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present"), ("b", "present"), ("c", "deleted")])
    );
    let resources = h.resources(agent.cluster_id, "include_deleted=true").await;
    let c = resources.iter().find(|r| r["name"] == "c").unwrap();
    assert!(c["deleted_at"].is_string());
    let c_detail = h
        .get(&format!(
            "/api/v1/projects/prod/clusters/{}/resources/{}",
            agent.cluster_id,
            c["id"].as_str().unwrap()
        ))
        .await;
    assert_eq!(
        c_detail["object"]["metadata"]["name"], "c",
        "the tombstone keeps the last state"
    );
    // Present-only listing leaves the tombstone out.
    assert_eq!(
        h.resources(agent.cluster_id, "collection=v1/nodes")
            .await
            .len(),
        2
    );
    // Deletion inference is per collection: other collections are untouched.
    conn.snapshot(
        "apps/v1/deployments",
        &[deployment("shop", "web", "dw", "5")],
    )
    .await;
    assert_eq!(h.names(agent.cluster_id, "v1/nodes").await.len(), 3);

    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["collections"][0]["collection"], "v1/nodes");
    assert_eq!(cluster["collections"][0]["state"], "synced");
    assert_eq!(cluster["collections"][0]["resource_count"], 2);
    assert!(cluster["collections"][0]["last_snapshot_completed_at"].is_string());
    assert_eq!(cluster["collections"][1]["state"], "never_synced");
    assert_eq!(cluster["inventory"]["counts"]["v1/nodes"], 2);
    assert_eq!(cluster["inventory"]["counts"]["apps/v1/deployments"], 1);
    assert_eq!(cluster["inventory"]["stale"], false);
    assert!(cluster["inventory"]["last_observed_at"].is_string());
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn incomplete_snapshots_infer_no_deletions() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    let all = [
        node("a", "ua", "1"),
        node("b", "ub", "1"),
        node("c", "uc", "1"),
    ];
    conn.snapshot("v1/nodes", &all).await;

    // Aborted.
    let id = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(id), &node("a", "ua", "1")).await;
    conn.send(
        "snapshot_abort",
        json!({"snapshot_id": id, "reason": "relisted"}),
    )
    .await;
    conn.snapshot_end(id, 1).await;
    conn.sync().await;
    // Replaced by a new snapshot before its end.
    let first = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(first), &node("a", "ua", "1")).await;
    let second = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(second), &node("b", "ub", "1")).await;
    conn.snapshot_end(first, 1).await;
    conn.sync().await;
    // A count mismatch.
    let id = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(id), &node("a", "ua", "1")).await;
    conn.snapshot_end(id, 3).await;
    conn.sync().await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present"), ("b", "present"), ("c", "present")])
    );
    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["collections"][0]["state"], "error");
    assert_eq!(
        cluster["collections"][0]["error"]["reason"],
        "snapshot_incomplete"
    );

    // A disconnect in the middle of a snapshot.
    let id = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(id), &node("a", "ua", "1")).await;
    conn.sync().await;
    conn.close().await;
    wait_disconnected(&h, &agent).await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    // A `snapshot_end` for a snapshot of an earlier connection infers nothing.
    conn.snapshot_end(id, 1).await;
    conn.send("upsert", {
        let mut body = observation(&node("d", "ud", "1"));
        body["object"] = node("d", "ud", "1");
        body
    })
    .await;
    conn.sync().await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[
            ("a", "present"),
            ("b", "present"),
            ("c", "present"),
            ("d", "present")
        ])
    );
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn duplicate_delivery_is_harmless() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    let id = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(id), &node("a", "ua", "5")).await;
    conn.upsert(Some(id), &node("b", "ub", "5")).await;
    conn.snapshot_end(id, 2).await;
    // A repeated `snapshot_end` is a no-op, and a repeated upsert changes nothing.
    conn.snapshot_end(id, 2).await;
    conn.upsert(None, &node("a", "ua", "5")).await;
    conn.sync().await;
    let before = h.resources(agent.cluster_id, "").await;

    // A reconnect lists the same resources again.
    conn.close().await;
    wait_disconnected(&h, &agent).await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "5"), node("b", "ub", "5")])
        .await;
    let after = h.resources(agent.cluster_id, "").await;
    assert_eq!(h.rows(agent.cluster_id).await, 2, "no duplicate rows");
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(old["id"], new["id"]);
        assert_eq!(old["first_observed_at"], new["first_observed_at"]);
        assert_eq!(new["state"], "present");
        assert!(
            time(&new["last_observed_at"]) > time(&old["last_observed_at"]),
            "an unchanged listing still confirms the resource"
        );
    }
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn reconnect_reconciles_without_false_deletions_or_duplicates() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot(
        "apps/v1/deployments",
        &[
            deployment("shop", "web", "dw", "10"),
            deployment("shop", "api", "da", "11"),
            deployment("ops", "cron", "dc", "12"),
        ],
    )
    .await;
    conn.close().await;
    wait_disconnected(&h, &agent).await;

    // While disconnected the inventory stays, marked stale.
    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["connection"]["state"], "disconnected");
    assert_eq!(cluster["connection"]["connected_since"], Value::Null);
    assert!(cluster["connection"]["last_seen_at"].is_string());
    assert_eq!(cluster["inventory"]["stale"], true);
    assert_eq!(cluster["inventory"]["counts"]["apps/v1/deployments"], 3);
    assert_eq!(cluster["collections"][2]["state"], "synced");

    // Meanwhile `api` was deleted, `web` changed, and `jobs` created.
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot(
        "apps/v1/deployments",
        &[
            deployment("shop", "web", "dw", "20"),
            deployment("ops", "cron", "dc", "12"),
            deployment("ops", "jobs", "dj", "21"),
        ],
    )
    .await;
    assert_eq!(
        h.names(agent.cluster_id, "apps/v1/deployments").await,
        pairs(&[
            ("cron", "present"),
            ("jobs", "present"),
            ("api", "deleted"),
            ("web", "present"),
        ])
    );
    assert_eq!(h.rows(agent.cluster_id).await, 4);
    let web = h
        .resources(agent.cluster_id, "search=web")
        .await
        .pop()
        .unwrap();
    assert_eq!(web["resource_version"], "20");
    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["connection"]["state"], "connected");
    assert!(cluster["connection"]["connected_since"].is_string());
    assert_eq!(cluster["connection"]["kubernetes_version"], "v1.35.1");
    assert_eq!(cluster["inventory"]["stale"], false);
    conn.close().await;
    h.finish().await;
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_epoch_fence_stops_a_superseded_connection() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut old = h.connect(&agent, "v1.35.1").await;
    old.snapshot("v1/nodes", &[node("a", "ua", "1")]).await;

    // Another server replica accepts a newer connection for the source: the epoch moves
    // on before this process hears about it.
    sqlx::query("UPDATE sources SET sync_epoch = sync_epoch + 1 WHERE id = $1")
        .bind(agent.source_id)
        .execute(&h.pool)
        .await
        .unwrap();
    // A delayed upsert from the old connection, for a resource never persisted, and an
    // end that would infer `a` deleted.
    let id = old.snapshot_start("v1/nodes").await;
    old.upsert(Some(id), &node("ghost", "ug", "2")).await;
    old.snapshot_end(id, 1).await;
    assert_eq!(old.expect_close().await, 4009);
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present")]),
        "nothing from the superseded connection was persisted"
    );

    let mut new = h.connect(&agent, "v1.35.1").await;
    new.snapshot("v1/nodes", &[node("a", "ua", "1")]).await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present")])
    );
    new.close().await;
    h.finish().await;
}

#[tokio::test]
async fn a_revoked_agent_cannot_persist_observations() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "1")]).await;
    // Revoke in the database only, so the notification cannot close the connection
    // first: the ingest transaction's own check must stop it.
    sqlx::query(
        "UPDATE agents SET revoked_at = now(), revocation_reason = 'revoked' WHERE id = $1",
    )
    .bind(agent.agent_id)
    .execute(&h.pool)
    .await
    .unwrap();
    conn.upsert(None, &node("b", "ub", "1")).await;
    assert_eq!(conn.expect_close().await, 4003);
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present")]),
        "revocation keeps inventory but persists nothing new"
    );
    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["agent"]["status"], "revoked");
    h.finish().await;
}

#[tokio::test]
async fn resource_versions_order_content_on_new_clusters_only() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "100")]).await;
    // A stale list after a reconnect: a lower resource version with a newer order key.
    let id = conn.snapshot_start("v1/nodes").await;
    let mut stale = node("a", "ua", "99");
    stale["status"]["nodeInfo"]["osImage"] = json!("stale");
    conn.upsert(Some(id), &stale).await;
    conn.snapshot_end(id, 1).await;
    conn.sync().await;
    let a = h.resources(agent.cluster_id, "").await.pop().unwrap();
    assert_eq!(a["resource_version"], "100", "older content is rejected");
    assert_eq!(
        a["state"], "present",
        "but the listing still counts as seen"
    );
    // A non-decimal version falls back to the order key.
    conn.upsert(None, &node("a", "ua", "abc")).await;
    conn.sync().await;
    let a = h.resources(agent.cluster_id, "").await.pop().unwrap();
    assert_eq!(a["resource_version"], "abc");
    conn.close().await;
    wait_disconnected(&h, &agent).await;

    // A cluster older than 1.35 orders content by order key alone.
    let mut conn = h.connect(&agent, "v1.34.2").await;
    conn.upsert(None, &node("a", "ua", "100")).await;
    conn.upsert(None, &node("a", "ua", "7")).await;
    conn.sync().await;
    let a = h.resources(agent.cluster_id, "").await.pop().unwrap();
    assert_eq!(a["resource_version"], "7");
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn an_upsert_for_a_tombstoned_uid_restores_it_as_an_anomaly() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "5"), node("b", "ub", "5")])
        .await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "5")]).await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present"), ("b", "deleted")])
    );
    // A lower resource version than the tombstone does not bring it back.
    conn.upsert(None, &node("b", "ub", "4")).await;
    conn.sync().await;
    assert_eq!(h.names(agent.cluster_id, "v1/nodes").await[1].1, "deleted");
    conn.upsert(None, &node("b", "ub", "6")).await;
    conn.sync().await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present"), ("b", "present")])
    );
    let reversals: i64 = sqlx::query_scalar(
        "SELECT tombstone_reversals FROM inventory_collections \
         WHERE source_id = $1 AND collection = 'v1/nodes'",
    )
    .bind(agent.source_id)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(reversals, 1);
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn a_replacement_with_the_same_name_is_a_new_resource() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot(
        "apps/v1/deployments",
        &[deployment("shop", "web", "old", "1")],
    )
    .await;
    conn.delete(&deployment("shop", "web", "old", "2")).await;
    conn.upsert(None, &deployment("shop", "web", "new", "3"))
        .await;
    conn.sync().await;
    let all = h.resources(agent.cluster_id, "include_deleted=true").await;
    let states: Vec<(&str, &str)> = all
        .iter()
        .map(|r| (r["uid"].as_str().unwrap(), r["state"].as_str().unwrap()))
        .collect();
    assert_eq!(states.len(), 2);
    assert!(states.contains(&("old", "deleted")));
    assert!(states.contains(&("new", "present")));
    let present = h.resources(agent.cluster_id, "").await;
    assert_eq!(present.len(), 1);
    assert_eq!(present[0]["uid"], "new");
    // The tombstone keeps the delete's resource version.
    let old = all.iter().find(|r| r["uid"] == "old").unwrap();
    assert_eq!(old["resource_version"], "2");
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn a_collection_error_keeps_prior_inventory() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "1"), node("b", "ub", "1")])
        .await;
    // The agent loses permission and its relist fails part way.
    let id = conn.snapshot_start("v1/nodes").await;
    conn.upsert(Some(id), &node("a", "ua", "1")).await;
    conn.send(
        "snapshot_abort",
        json!({"snapshot_id": id, "reason": "forbidden"}),
    )
    .await;
    conn.send(
        "collection_error",
        json!({
            "collection": "v1/nodes",
            "scope": {"namespace": null},
            "reason": "forbidden",
            "message": "nodes is forbidden: User \"system:serviceaccount:vn-agent:vn-agent\" cannot list resource \"nodes\"",
        }),
    )
    .await;
    conn.sync().await;
    assert_eq!(
        h.names(agent.cluster_id, "v1/nodes").await,
        pairs(&[("a", "present"), ("b", "present")])
    );
    let cluster = h.cluster(agent.cluster_id).await;
    let nodes = &cluster["collections"][0];
    assert_eq!(nodes["state"], "error");
    assert_eq!(nodes["error"]["reason"], "forbidden");
    assert!(
        nodes["error"]["message"]
            .as_str()
            .unwrap()
            .contains("forbidden")
    );
    assert!(nodes["error"]["observed_at"].is_string());
    assert_eq!(nodes["resource_count"], 2);

    // A syncing collection, then a completed snapshot clears the error.
    let id = conn.snapshot_start("v1/namespaces").await;
    conn.sync().await;
    assert_eq!(
        h.cluster(agent.cluster_id).await["collections"][1]["state"],
        "syncing"
    );
    conn.snapshot_end(id, 0).await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "1"), node("b", "ub", "1")])
        .await;
    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["collections"][0]["state"], "synced");
    assert_eq!(cluster["collections"][0]["error"], Value::Null);
    assert_eq!(cluster["collections"][1]["state"], "synced");
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn invalid_and_unknown_messages_are_answered_and_ignored() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.send(
        "snapshot_start",
        json!({"snapshot_id": Uuid::from_u128(1), "collection": "v1/secrets", "scope": {}}),
    )
    .await;
    let mut no_namespace = observation(&deployment("shop", "web", "dw", "1"));
    no_namespace["namespace"] = Value::Null;
    no_namespace["object"] = json!({});
    let bad = conn.send("upsert", no_namespace).await;
    conn.sync().await;
    assert_eq!(conn.notices.len(), 2, "{:?}", conn.notices);
    assert_eq!(conn.notices[0]["code"], "unsupported_collection");
    assert_eq!(conn.notices[1]["code"], "invalid_message");
    assert_eq!(conn.notices[1]["ref_seq"], bad);
    assert_eq!(h.rows(agent.cluster_id).await, 0);
    conn.close().await;
    h.finish().await;
}

// ---------------------------------------------------------------------------
// Persistence and sanitization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inventory_survives_a_server_restart() {
    let mut h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "1")]).await;
    conn.snapshot(
        "apps/v1/deployments",
        &[deployment("shop", "web", "dw", "1")],
    )
    .await;
    h.restart().await;
    // The old process is gone; its connection is closed at startup.
    let cluster = h.cluster(agent.cluster_id).await;
    assert_eq!(cluster["connection"]["state"], "disconnected");
    assert_eq!(cluster["inventory"]["stale"], true);
    assert_eq!(cluster["inventory"]["counts"]["v1/nodes"], 1);
    assert_eq!(cluster["inventory"]["counts"]["apps/v1/deployments"], 1);
    assert_eq!(h.resources(agent.cluster_id, "").await.len(), 2);
    drop(conn);
    // A new connection to the new process reconciles on top of it.
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "1")]).await;
    assert_eq!(h.rows(agent.cluster_id).await, 2);
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn the_server_sanitizes_again_and_stores_truncated_objects_by_identity() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    // An agent that did not sanitize.
    let mut leaky = deployment("shop", "web", "dw", "1");
    leaky["metadata"]["managedFields"] = json!([{"manager": "kubectl"}]);
    leaky["metadata"]["annotations"] = json!({
        "kubectl.kubernetes.io/last-applied-configuration": "{\"env\":\"hunter2\"}",
        "team": "shop",
    });
    conn.upsert(None, &leaky).await;
    let mut truncated = observation(&deployment("shop", "huge", "dh", "1"));
    truncated["truncated"] = json!(true);
    conn.send("upsert", truncated).await;
    conn.sync().await;
    let resources = h.resources(agent.cluster_id, "").await;
    let path = |name: &str| {
        let id = resources.iter().find(|r| r["name"] == name).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        format!(
            "/api/v1/projects/prod/clusters/{}/resources/{id}",
            agent.cluster_id
        )
    };
    let web = h.get(&path("web")).await;
    let text = web["object"].to_string();
    assert!(!text.contains("hunter2"), "{text}");
    assert!(!text.contains("managedFields"));
    assert_eq!(
        web["object"]["metadata"]["annotations"],
        json!({"team": "shop"})
    );
    assert_eq!(
        web["object"]["spec"]["template"]["spec"]["containers"][0]["env"],
        json!([{"name": "PASSWORD"}])
    );
    assert_eq!(web["truncated"], false);
    let huge = h.get(&path("huge")).await;
    assert_eq!(huge["truncated"], true);
    assert_eq!(
        huge["object"],
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "huge", "namespace": "shop", "uid": "dh", "resourceVersion": "1"},
        })
    );
    assert_eq!(
        huge["summary"],
        json!({"replicas": null, "ready_replicas": null, "images": null})
    );
    conn.close().await;
    h.finish().await;
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_inventory_api_filters_pages_and_summarizes() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("worker-1", "n1", "1")])
        .await;
    conn.snapshot(
        "v1/namespaces",
        &[json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": "shop", "uid": "ns1", "resourceVersion": "1"},
            "status": {"phase": "Active"},
        })],
    )
    .await;
    let deployments: Vec<Value> = (0..7)
        .map(|i| {
            let namespace = if i % 2 == 0 { "shop" } else { "ops" };
            deployment(namespace, &format!("App-{i}"), &format!("d{i}"), "1")
        })
        .collect();
    conn.snapshot("apps/v1/deployments", &deployments).await;
    conn.snapshot(
        "apps/v1/daemonsets",
        &[json!({
            "apiVersion": "apps/v1", "kind": "DaemonSet",
            "metadata": {"name": "agent", "namespace": "ops", "uid": "ds1", "resourceVersion": "1"},
            "spec": {"template": {"spec": {"containers": [{"image": "agent:2"}]}}},
            "status": {"desiredNumberScheduled": 3, "numberReady": 2},
        })],
    )
    .await;
    conn.delete(&deployment("ops", "App-1", "d1", "2")).await;
    conn.sync().await;
    let base = format!(
        "/api/v1/projects/prod/clusters/{}/resources",
        agent.cluster_id
    );

    // Ordering: collection, namespace (cluster-scoped first within their collection), name.
    let all = h.resources(agent.cluster_id, "").await;
    let order: Vec<(&str, &str)> = all
        .iter()
        .map(|r| {
            (
                r["collection"].as_str().unwrap(),
                r["name"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(order.len(), 9);
    assert_eq!(order[0], ("apps/v1/daemonsets", "agent"));
    assert_eq!(order[1], ("apps/v1/deployments", "App-3"));
    assert_eq!(order[7], ("v1/namespaces", "shop"));
    assert_eq!(order[8], ("v1/nodes", "worker-1"));

    // Filters.
    let shop = h
        .resources(
            agent.cluster_id,
            "collection=apps/v1/deployments&namespace=shop",
        )
        .await;
    assert_eq!(shop.len(), 4);
    let search = h.resources(agent.cluster_id, "search=app-").await;
    assert_eq!(search.len(), 6, "search is a case-insensitive substring");
    let search = h
        .resources(agent.cluster_id, "search=APP-1&include_deleted=true")
        .await;
    assert_eq!(search.len(), 1);
    assert_eq!(search[0]["state"], "deleted");
    assert!(
        h.resources(agent.cluster_id, "search=%25").await.is_empty(),
        "wildcards are literal"
    );

    // Pagination.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = match &cursor {
            Some(c) => format!("?limit=2&include_deleted=true&cursor={c}"),
            None => "?limit=2&include_deleted=true".into(),
        };
        let page = h.get(&format!("{base}{query}")).await;
        let resources = page["resources"].as_array().unwrap();
        assert!(resources.len() <= 2);
        seen.extend(resources.iter().map(|r| r["id"].clone()));
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    let everything = h
        .resources(agent.cluster_id, "include_deleted=true&limit=500")
        .await;
    assert_eq!(seen.len(), 10);
    assert_eq!(
        seen,
        everything
            .iter()
            .map(|r| r["id"].clone())
            .collect::<Vec<_>>()
    );
    let page = h.get(&format!("{base}?limit=500")).await;
    assert_eq!(page["next_cursor"], Value::Null);

    // Bad parameters.
    for query in [
        "limit=0",
        "limit=501",
        "collection=v1/secrets",
        "include_deleted=maybe",
        "cursor=garbage",
    ] {
        let (status, body) = h.get_as(Some(&h.admin), &format!("{base}?{query}")).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{query}: {body:?}"
        );
        assert_eq!(body["error"], "invalid_request");
    }

    // Summaries.
    let summary = |name: &str| all.iter().find(|r| r["name"] == name).unwrap()["summary"].clone();
    assert_eq!(
        summary("worker-1"),
        json!({
            "ready": true,
            "roles": ["control-plane"],
            "kubelet_version": "v1.37.0",
            "os_image": "Debian GNU/Linux 12",
            "internal_ip": "172.18.0.2",
            "cpu": "4",
            "memory": "8Gi",
        })
    );
    assert_eq!(summary("shop"), json!({"phase": "Active"}));
    assert_eq!(
        summary("App-0"),
        json!({"replicas": 2, "ready_replicas": 1, "images": ["example/App-0:1"]})
    );
    assert_eq!(
        summary("agent"),
        json!({"desired": 3, "ready": 2, "images": ["agent:2"]})
    );
    let node = all.iter().find(|r| r["name"] == "worker-1").unwrap();
    assert_eq!(node["kind"], "Node");
    assert_eq!(node["namespace"], Value::Null);
    assert_eq!(node["uid"], "n1");
    let detail = h
        .get(&format!("{base}/{}", node["id"].as_str().unwrap()))
        .await;
    assert_eq!(detail["name"], "worker-1");
    assert!(detail["object"]["status"].get("images").is_none());
    assert!(detail["object"]["metadata"].get("managedFields").is_none());

    // Cluster list.
    let list = h.get("/api/v1/projects/prod/clusters").await;
    let clusters = list["clusters"].as_array().unwrap();
    assert_eq!(clusters.len(), 1);
    let cluster = &clusters[0];
    assert_eq!(cluster["id"], json!(agent.cluster_id));
    assert_eq!(cluster["display_name"], "east");
    assert_eq!(cluster["source_id"], json!(agent.source_id));
    assert_eq!(cluster["agent"]["id"], json!(agent.agent_id));
    assert_eq!(cluster["agent"]["status"], "active");
    assert_eq!(cluster["agent"]["agent_version"], "0.1.0");
    let names: Vec<&str> = cluster["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["collection"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "v1/nodes",
            "v1/namespaces",
            "apps/v1/deployments",
            "apps/v1/statefulsets",
            "apps/v1/daemonsets"
        ]
    );
    assert_eq!(cluster["inventory"]["counts"]["apps/v1/deployments"], 6);
    assert_eq!(cluster["inventory"]["counts"]["apps/v1/statefulsets"], 0);
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn the_inventory_api_is_for_project_members_only() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let other = h.enroll("other", "west").await;
    let never = h.enroll("prod", "north").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    conn.snapshot("v1/nodes", &[node("a", "ua", "1")]).await;
    let resource_id = h.resources(agent.cluster_id, "").await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let paths = [
        "/api/v1/projects/prod/clusters".to_owned(),
        format!("/api/v1/projects/prod/clusters/{}", agent.cluster_id),
        format!(
            "/api/v1/projects/prod/clusters/{}/resources",
            agent.cluster_id
        ),
        format!(
            "/api/v1/projects/prod/clusters/{}/resources/{resource_id}",
            agent.cluster_id
        ),
    ];

    let viewer = h.member_session("victor", "prod", "viewer").await;
    let operator = h.member_session("olga", "prod", "operator").await;
    let outsider = h.member_session("oscar", "other", "viewer").await;
    for path in &paths {
        for session in [&viewer, &operator, &h.admin] {
            let (status, body) = h.get_as(Some(session), path).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body:?}");
        }
        let (status, _) = h.get_as(Some(&outsider), path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        let (status, _) = h.get_as(None, path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }

    // A cluster of another project is not found through this project, even for an
    // installation admin, and neither are its resources.
    for path in [
        format!("/api/v1/projects/prod/clusters/{}", other.cluster_id),
        format!(
            "/api/v1/projects/prod/clusters/{}/resources",
            other.cluster_id
        ),
        format!(
            "/api/v1/projects/prod/clusters/{}/resources/{resource_id}",
            other.cluster_id
        ),
        format!(
            "/api/v1/projects/prod/clusters/{}/resources/{}",
            agent.cluster_id,
            Uuid::from_u128(7)
        ),
    ] {
        let (status, body) = h.get_as(Some(&h.admin), &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body:?}");
        assert_eq!(body["error"], "not_found");
    }
    let (status, body) = h
        .get_as(
            Some(&outsider),
            &format!("/api/v1/projects/other/clusters/{}", other.cluster_id),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");

    // A cluster whose agent never connected.
    let list = h.get("/api/v1/projects/prod/clusters").await;
    let names: Vec<&str> = list["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["display_name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["east", "north"], "ordered by display name");
    let north = h.cluster(never.cluster_id).await;
    assert_eq!(north["connection"]["state"], "never_connected");
    assert_eq!(north["connection"]["last_seen_at"], Value::Null);
    assert_eq!(north["inventory"]["stale"], true);
    assert_eq!(north["inventory"]["last_observed_at"], Value::Null);
    assert_eq!(north["collections"][0]["state"], "never_synced");
    conn.close().await;
    h.finish().await;
}

#[tokio::test]
async fn batches_are_acknowledged_cumulatively_within_the_window() {
    let h = harness!();
    let agent = h.enroll("prod", "east").await;
    let mut conn = h.connect(&agent, "v1.35.1").await;
    let window = conn.welcome["body"]["ack_window"].as_u64().unwrap();
    assert_eq!(window, 64);
    // A full window of messages in one burst, then everything is acknowledged.
    let id = conn.snapshot_start("apps/v1/deployments").await;
    for i in 0..(window - 3) {
        conn.upsert(
            Some(id),
            &deployment("shop", &format!("d{i}"), &format!("u{i}"), "1"),
        )
        .await;
    }
    conn.snapshot_end(id, window - 3).await;
    conn.sync().await;
    assert_eq!(
        h.rows(agent.cluster_id).await,
        i64::try_from(window - 3).unwrap()
    );
    conn.close().await;
    h.finish().await;
}
