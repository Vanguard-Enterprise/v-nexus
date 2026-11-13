//! End-to-end sign-in and scoped access tests against a mock OIDC provider and a real
//! PostgreSQL database.
//!
//! These tests need PostgreSQL. Set `DATABASE_URL` to a server where the user may create
//! databases (for example the Compose database, `postgres://vn:vn@localhost:5432/vn`).
//! Each test creates and drops its own database. Without `DATABASE_URL` the tests pass
//! after printing that they were skipped.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{TimeDelta, Utc};
use cookie::Cookie;
use http_body_util::BodyExt;
use openidconnect::core::{
    CoreGenderClaim, CoreHmacKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    AccessToken, AdditionalClaims, Audience, EndUserEmail, EndUserName, IdToken, IdTokenClaims,
    IssuerUrl, JsonWebKeyId, LocalizedClaim, Nonce, PrivateSigningKey, StandardClaims,
    SubjectIdentifier,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use tower::ServiceExt;
use vn_server::{AppState, AuthService, router};

const CLIENT_ID: &str = "vn-test";
const CLIENT_SECRET: &str = "test-client-secret";
const PUBLIC_ORIGIN: &str = "https://vn.example.com";
const SESSION_COOKIE: &str = "__Host-vn_session";
const LOGIN_COOKIE: &str = "__Host-vn_login";
const ADMIN_GROUP: &str = "vn-admins";

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

        let mut url = url::Url::parse(&admin_url).expect("DATABASE_URL is a URL");
        url.set_path(&name);
        let pool = PgPoolOptions::new()
            .max_connections(4)
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
// Mock OIDC provider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TestClaims {
    #[serde(flatten)]
    claims: serde_json::Map<String, Value>,
}

impl AdditionalClaims for TestClaims {}

type TestIdToken = IdToken<
    TestClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// A person the mock provider can authenticate.
#[derive(Clone)]
struct MockUser {
    subject: &'static str,
    email: &'static str,
    name: &'static str,
    /// Groups placed in the ID token.
    id_token_groups: Option<Vec<&'static str>>,
    /// Groups placed only in the userinfo response.
    userinfo_groups: Option<Vec<&'static str>>,
}

fn alice() -> MockUser {
    MockUser {
        subject: "alice",
        email: "alice@example.com",
        name: "Alice Admin",
        id_token_groups: Some(vec!["staff", ADMIN_GROUP]),
        userinfo_groups: None,
    }
}

fn bob() -> MockUser {
    MockUser {
        subject: "bob",
        email: "bob@example.com",
        name: "Bob Viewer",
        id_token_groups: Some(vec!["staff"]),
        userinfo_groups: None,
    }
}

/// What the provider remembers between the authorization request and the token request.
struct Grant {
    user: MockUser,
    nonce: String,
    code_challenge: String,
    redirect_uri: String,
}

struct MockInner {
    issuer: String,
    /// Key ID of the RSA key ID tokens are signed with.
    signing_kid: Mutex<String>,
    /// Key ID of the RSA key published at the JWKS endpoint.
    published_kid: Mutex<String>,
    /// Sign ID tokens with HS256 and the client secret instead.
    sign_with_client_secret: AtomicBool,
    jwks_fetches: AtomicUsize,
    grants: Mutex<HashMap<String, Grant>>,
    userinfo: Mutex<HashMap<String, Value>>,
}

#[derive(Clone)]
struct MockProvider(Arc<MockInner>);

/// Generating an RSA key is slow, so one key serves every test in this binary.
fn rsa_pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    })
}

/// The RSA key under key ID `kid`. Every key ID shares one key pair: verifiers look keys
/// up by ID, so a new ID is enough to model a rotation.
fn rsa_key(kid: &str) -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(rsa_pem(), Some(JsonWebKeyId::new(kid.into()))).unwrap()
}

impl MockProvider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let provider = Self(Arc::new(MockInner {
            issuer,
            signing_kid: Mutex::new("k1".into()),
            published_kid: Mutex::new("k1".into()),
            sign_with_client_secret: AtomicBool::new(false),
            jwks_fetches: AtomicUsize::new(0),
            grants: Mutex::default(),
            userinfo: Mutex::default(),
        }));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo))
            .with_state(provider.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        provider
    }

    fn issuer(&self) -> &str {
        &self.0.issuer
    }

    /// Plays the provider's authorization endpoint: checks the request VN sent the
    /// browser to and returns the code the provider would redirect back with.
    fn authorize(&self, authorize_url: &str, user: MockUser) -> (String, String) {
        let url = url::Url::parse(authorize_url).unwrap();
        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            format!("{}/authorize", self.issuer())
        );
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["redirect_uri"],
            format!("{PUBLIC_ORIGIN}/api/v1/auth/callback")
        );
        let scopes: Vec<&str> = params["scope"].split(' ').collect();
        assert!(
            scopes.contains(&"openid") && scopes.contains(&"groups"),
            "{scopes:?}"
        );
        assert_eq!(scopes.iter().filter(|s| **s == "openid").count(), 1);

        let code = random_hex(16);
        self.0.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                user,
                nonce: params["nonce"].clone(),
                code_challenge: params["code_challenge"].clone(),
                redirect_uri: params["redirect_uri"].clone(),
            },
        );
        (code, params["state"].clone())
    }

    /// Replaces the signing key with a new one under key ID `kid`, as a provider rotating
    /// its keys does.
    fn rotate(&self, kid: &str) {
        *self.0.signing_kid.lock().unwrap() = kid.into();
        *self.0.published_kid.lock().unwrap() = kid.into();
    }

    /// Signs ID tokens with a key under `kid` that the JWKS endpoint never publishes.
    fn sign_with_unpublished_key(&self, kid: &str) {
        *self.0.signing_kid.lock().unwrap() = kid.into();
    }

    /// Signs ID tokens with HS256 keyed by the client secret, and advertises only HS256.
    fn sign_with_client_secret(&self) {
        self.0.sign_with_client_secret.store(true, Ordering::SeqCst);
    }

    fn jwks_fetches(&self) -> usize {
        self.0.jwks_fetches.load(Ordering::SeqCst)
    }

    /// Changes the nonce the provider will put in the ID token for `code`.
    fn tamper_nonce(&self, code: &str) {
        self.0.grants.lock().unwrap().get_mut(code).unwrap().nonce = "forged".into();
    }
}

async fn discovery(State(p): State<MockProvider>) -> Json<Value> {
    let issuer = p.issuer();
    let alg = if p.0.sign_with_client_secret.load(Ordering::SeqCst) {
        "HS256"
    } else {
        "RS256"
    };
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [alg],
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks(State(p): State<MockProvider>) -> Json<Value> {
    p.0.jwks_fetches.fetch_add(1, Ordering::SeqCst);
    let key = rsa_key(&p.0.published_kid.lock().unwrap());
    Json(json!({ "keys": [key.as_verification_key()] }))
}

fn oauth_error(code: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": code }))).into_response()
}

async fn token(
    State(p): State<MockProvider>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let expected_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()) != Some(expected_auth.as_bytes()) {
        return oauth_error("invalid_client");
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return oauth_error("unsupported_grant_type");
    }
    let Some(grant) = form
        .get("code")
        .and_then(|code| p.0.grants.lock().unwrap().remove(code))
    else {
        return oauth_error("invalid_grant");
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if challenge != grant.code_challenge || form.get("redirect_uri") != Some(&grant.redirect_uri) {
        return oauth_error("invalid_grant");
    }

    let user = grant.user;
    let access_token = random_hex(16);
    let mut extra = serde_json::Map::new();
    if let Some(groups) = &user.id_token_groups {
        extra.insert("groups".into(), json!(groups));
    }
    let mut name = LocalizedClaim::new();
    name.insert(None, EndUserName::new(user.name.into()));
    let now = Utc::now();
    let claims = IdTokenClaims::new(
        IssuerUrl::new(p.issuer().into()).unwrap(),
        vec![Audience::new(CLIENT_ID.into())],
        now + TimeDelta::minutes(5),
        now,
        StandardClaims::new(SubjectIdentifier::new(user.subject.into()))
            .set_email(Some(EndUserEmail::new(user.email.into())))
            .set_name(Some(name)),
        TestClaims { claims: extra },
    )
    .set_nonce(Some(Nonce::new(grant.nonce)));
    let id_token = if p.0.sign_with_client_secret.load(Ordering::SeqCst) {
        // No at_hash, so nothing but the algorithm check can stop this token: the
        // crate's verifier accepts HS256 keyed by the client secret.
        TestIdToken::new(
            claims,
            &CoreHmacKey::new(CLIENT_SECRET),
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        )
    } else {
        let key = rsa_key(&p.0.signing_kid.lock().unwrap());
        TestIdToken::new(
            claims,
            &key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&AccessToken::new(access_token.clone())),
            None,
        )
    }
    .unwrap();

    let mut info = json!({ "sub": user.subject });
    if let Some(groups) = &user.userinfo_groups {
        info["groups"] = json!(groups);
    }
    p.0.userinfo
        .lock()
        .unwrap()
        .insert(access_token.clone(), info);

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    }))
    .into_response()
}

async fn userinfo(State(p): State<MockProvider>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    match p.0.userinfo.lock().unwrap().get(token) {
        Some(info) => Json(info.clone()).into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

// ---------------------------------------------------------------------------
// VN under test
// ---------------------------------------------------------------------------

struct Harness {
    db: TestDb,
    provider: MockProvider,
    app: Router,
}

impl Harness {
    async fn start() -> Option<Self> {
        Self::start_with(&format!("{{claim: groups, values: [{ADMIN_GROUP}]}}"), "").await
    }

    /// Starts with `admin_yaml` as the `auth.admin` mapping and `session_yaml` appended
    /// to the `auth` block.
    async fn start_with(admin_yaml: &str, session_yaml: &str) -> Option<Self> {
        let db = TestDb::create().await?;
        let provider = MockProvider::start().await;
        let config = vn_config::Config::from_yaml(&format!(
            "version: 1
server: {{listen: 127.0.0.1:0}}
database: {{url_env: VN_DATABASE_URL}}
auth:
  issuer_url: {issuer}
  client_id: {CLIENT_ID}
  client_secret_env: VN_OIDC_CLIENT_SECRET
  public_url: {PUBLIC_ORIGIN}
  allow_insecure_http: true
  scopes: [openid, profile, email, groups]
  admin: {admin_yaml}
{session_yaml}",
            issuer = provider.issuer(),
        ))
        .unwrap();
        let auth = config.auth.unwrap();
        let secret = auth
            .resolve_client_secret_with(|_| Some(CLIENT_SECRET.into()))
            .unwrap();
        let state =
            AppState::new(db.pool.clone()).with_auth(AuthService::new(&auth, &secret).unwrap());
        let app = router(state, None);
        Some(Self { db, provider, app })
    }

    async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
        TestResponse {
            status,
            headers,
            json,
        }
    }

    /// Runs the whole browser sign-in and returns the session cookie value.
    async fn sign_in(&self, user: MockUser) -> String {
        let login = self.start_login("/projects?tab=all").await;
        let (code, state) = self.provider.authorize(&login.location, user);
        let callback = self
            .callback(&code, &state, Some(&login.login_cookie))
            .await;
        assert_eq!(callback.location(), "/projects?tab=all");
        callback
            .cookie(SESSION_COOKIE)
            .expect("callback sets the session cookie")
            .value()
            .to_owned()
    }

    async fn start_login(&self, return_to: &str) -> LoginStart {
        let response = self
            .send(
                Request::get(format!("/api/v1/auth/login?return_to={return_to}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::SEE_OTHER,
            "{:?}",
            response.json
        );
        let cookie = response.cookie(LOGIN_COOKIE).expect("login cookie");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(cookie::SameSite::Lax));
        LoginStart {
            location: response.location(),
            login_cookie: cookie.value().to_owned(),
        }
    }

    async fn callback(&self, code: &str, state: &str, login_cookie: Option<&str>) -> TestResponse {
        let mut request = Request::get(format!("/api/v1/auth/callback?code={code}&state={state}"));
        if let Some(value) = login_cookie {
            request = request.header(header::COOKIE, format!("{LOGIN_COOKIE}={value}"));
        }
        let response = self.send(request.body(Body::empty()).unwrap()).await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        response
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
        self.send(write_request(session, method, uri, body)).await
    }

    async fn audit_actions(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT action FROM audit_events ORDER BY id")
            .fetch_all(&self.db.pool)
            .await
            .unwrap()
    }

    async fn finish(self) {
        self.db.drop_database().await;
    }
}

fn write_request(session: &str, method: Method, uri: &str, body: Value) -> Request<Body> {
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
    request.unwrap()
}

struct LoginStart {
    location: String,
    login_cookie: String,
}

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
}

impl TestResponse {
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_owned()
    }

    fn cookie(&self, name: &str) -> Option<Cookie<'static>> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| Cookie::parse(v.to_str().unwrap().to_owned()).unwrap())
            .find(|c| c.name() == name)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn browser_sign_in_creates_a_hashed_server_side_session() {
    let h = harness!(Harness::start());

    let login = h.start_login("/projects?tab=all").await;
    let (code, state) = h.provider.authorize(&login.location, alice());
    let callback = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert_eq!(callback.location(), "/projects?tab=all");

    let session = callback.cookie(SESSION_COOKIE).expect("session cookie");
    assert_eq!(session.http_only(), Some(true));
    assert_eq!(session.secure(), Some(true));
    assert_eq!(session.same_site(), Some(cookie::SameSite::Lax));
    assert_eq!(session.path(), Some("/"));
    assert_eq!(session.max_age(), Some(cookie::time::Duration::hours(12)));
    let cleared = callback.cookie(LOGIN_COOKIE).expect("login cookie removal");
    assert_eq!(cleared.value(), "");
    assert_eq!(cleared.max_age(), Some(cookie::time::Duration::ZERO));

    // Only a hash of the token is stored.
    let token = session.value().to_owned();
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_all(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(stored, [Sha256::digest(token.as_bytes()).to_vec()]);

    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json["user"]["issuer"], h.provider.issuer());
    assert_eq!(me.json["user"]["subject"], "alice");
    assert_eq!(me.json["user"]["email"], "alice@example.com");
    assert_eq!(me.json["user"]["display_name"], "Alice Admin");
    assert_eq!(me.json["installation_roles"], json!(["admin"]));

    // Nothing secret reaches the audit log.
    let details: Vec<Value> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&h.db.pool)
        .await
        .unwrap();
    let details = serde_json::to_string(&details).unwrap();
    assert!(
        !details.contains(&token) && !details.contains(&code),
        "{details}"
    );
    assert_eq!(h.audit_actions().await, ["auth.login"]);

    h.finish().await;
}

#[tokio::test]
async fn logout_revokes_the_session() {
    let h = harness!(Harness::start());
    let token = h.sign_in(alice()).await;

    let logout = h
        .write(&token, Method::POST, "/api/v1/auth/logout", Value::Null)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let removal = logout.cookie(SESSION_COOKIE).expect("cookie removal");
    assert_eq!(removal.value(), "");
    assert_eq!(removal.max_age(), Some(cookie::time::Duration::ZERO));

    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.json["error"], "unauthorized");
    let revoked: bool = sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM sessions")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert!(revoked);
    assert_eq!(h.audit_actions().await, ["auth.login", "auth.logout"]);

    h.finish().await;
}

#[tokio::test]
async fn callback_requires_the_browser_that_started_sign_in() {
    let h = harness!(Harness::start());
    let login = h.start_login("/").await;
    let (code, state) = h.provider.authorize(&login.location, alice());

    // No login cookie (a callback URL planted in another browser) or a different one.
    for cookie in [None, Some("someone-elses-state")] {
        let response = h.callback(&code, &state, cookie).await;
        assert_eq!(response.location(), "/?login_error=expired");
        assert!(response.cookie(SESSION_COOKIE).is_none());
    }

    // The real browser still completes, exactly once.
    let ok = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert!(ok.cookie(SESSION_COOKIE).is_some());
    let replay = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert_eq!(replay.location(), "/?login_error=expired");
    assert!(replay.cookie(SESSION_COOKIE).is_none());

    h.finish().await;
}

#[tokio::test]
async fn callback_rejects_an_id_token_with_the_wrong_nonce() {
    let h = harness!(Harness::start());
    let login = h.start_login("/").await;
    let (code, state) = h.provider.authorize(&login.location, alice());
    h.provider.tamper_nonce(&code);

    let response = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert_eq!(response.location(), "/?login_error=failed");
    assert!(response.cookie(SESSION_COOKIE).is_none());
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);

    h.finish().await;
}

/// Number of sessions stored, revoked or not.
async fn session_count(h: &Harness) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&h.db.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn signing_key_rotation_refetches_keys_once() {
    let h = harness!(Harness::start());
    h.sign_in(alice()).await;
    assert_eq!(h.provider.jwks_fetches(), 1);

    // The cached keys predate the rotation, so the first token signed with the new key
    // triggers one fetch, and later sign-ins use the refreshed keys.
    h.provider.rotate("k2");
    let token = h.sign_in(bob()).await;
    assert_eq!(h.provider.jwks_fetches(), 2);
    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.json["user"]["subject"], "bob");
    h.sign_in(alice()).await;
    assert_eq!(h.provider.jwks_fetches(), 2);

    h.finish().await;
}

#[tokio::test]
async fn id_token_signed_with_an_unpublished_key_is_rejected_after_one_refresh() {
    let h = harness!(Harness::start());
    h.sign_in(alice()).await;
    assert_eq!(h.provider.jwks_fetches(), 1);

    h.provider.sign_with_unpublished_key("never-published");
    let login = h.start_login("/").await;
    let (code, state) = h.provider.authorize(&login.location, bob());
    let response = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert_eq!(response.location(), "/?login_error=failed");
    assert!(response.cookie(SESSION_COOKIE).is_none());
    assert_eq!(h.provider.jwks_fetches(), 2);
    assert_eq!(session_count(&h).await, 1);

    h.finish().await;
}

#[tokio::test]
async fn id_tokens_signed_with_the_client_secret_are_rejected() {
    let h = harness!(Harness::start());
    h.provider.sign_with_client_secret();
    let login = h.start_login("/").await;
    let (code, state) = h.provider.authorize(&login.location, alice());
    let response = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert_eq!(response.location(), "/?login_error=failed");
    assert!(response.cookie(SESSION_COOKIE).is_none());
    assert_eq!(session_count(&h).await, 0);

    h.finish().await;
}

#[tokio::test]
async fn provider_errors_redirect_without_a_session() {
    let h = harness!(Harness::start());
    let login = h.start_login("/").await;
    let response = h
        .send(
            Request::get("/api/v1/auth/callback?error=access_denied&state=x")
                .header(
                    header::COOKIE,
                    format!("{LOGIN_COOKIE}={}", login.login_cookie),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.location(), "/?login_error=denied");
    h.finish().await;
}

#[tokio::test]
async fn admin_role_can_come_from_userinfo() {
    let h = harness!(Harness::start());
    let carol = MockUser {
        subject: "carol",
        email: "carol@example.com",
        name: "Carol",
        id_token_groups: None,
        userinfo_groups: Some(vec![ADMIN_GROUP]),
    };
    let token = h.sign_in(carol).await;
    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.json["installation_roles"], json!(["admin"]));

    let dave = MockUser {
        subject: "dave",
        email: "dave@example.com",
        name: "Dave",
        id_token_groups: None,
        userinfo_groups: Some(vec!["staff"]),
    };
    let token = h.sign_in(dave).await;
    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.json["installation_roles"], json!([]));

    h.finish().await;
}

#[tokio::test]
async fn admin_role_can_come_from_the_subject() {
    // Bob is not in the admin group, so only the subject can make him an admin.
    let h = harness!(Harness::start_with("{claim: sub, values: [bob]}", ""));
    let token = h.sign_in(bob()).await;
    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.json["user"]["subject"], "bob");
    assert_eq!(me.json["installation_roles"], json!(["admin"]));

    // Alice is in the admin group, which this mapping ignores.
    let token = h.sign_in(alice()).await;
    let me = h.get(&token, "/api/v1/auth/me").await;
    assert_eq!(me.json["installation_roles"], json!([]));

    h.finish().await;
}

#[tokio::test]
async fn sessions_end_after_idle_and_absolute_timeouts() {
    let h = harness!(Harness::start_with(
        &format!("{{claim: groups, values: [{ADMIN_GROUP}]}}"),
        "  session: {idle_timeout_minutes: 5, absolute_timeout_minutes: 60}\n"
    ));
    let token = h.sign_in(alice()).await;
    assert_eq!(
        h.get(&token, "/api/v1/auth/me").await.status,
        StatusCode::OK
    );

    // Idle for longer than the idle timeout.
    sqlx::query("UPDATE sessions SET created_at = created_at - interval '10 minutes', last_seen_at = last_seen_at - interval '6 minutes'")
        .execute(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(
        h.get(&token, "/api/v1/auth/me").await.status,
        StatusCode::UNAUTHORIZED
    );

    // Recently active, but past the absolute lifetime.
    let token = h.sign_in(alice()).await;
    sqlx::query("UPDATE sessions SET created_at = now() - interval '2 hours', last_seen_at = now(), expires_at = now() - interval '1 minute' WHERE revoked_at IS NULL")
        .execute(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(
        h.get(&token, "/api/v1/auth/me").await.status,
        StatusCode::UNAUTHORIZED
    );

    h.finish().await;
}

#[tokio::test]
async fn signing_in_again_revokes_the_previous_session() {
    let h = harness!(Harness::start());
    let first = h.sign_in(alice()).await;

    let login = h.start_login("/").await;
    let (code, state) = h.provider.authorize(&login.location, alice());
    let response = h
        .send(
            Request::get(format!("/api/v1/auth/callback?code={code}&state={state}"))
                .header(
                    header::COOKIE,
                    format!(
                        "{LOGIN_COOKIE}={}; {SESSION_COOKIE}={first}",
                        login.login_cookie
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let second = response.cookie(SESSION_COOKIE).unwrap().value().to_owned();
    assert_ne!(first, second);
    assert_eq!(
        h.get(&first, "/api/v1/auth/me").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.get(&second, "/api/v1/auth/me").await.status,
        StatusCode::OK
    );
    h.finish().await;
}

#[tokio::test]
async fn project_access_is_scoped_by_role() {
    let h = harness!(Harness::start());
    let admin = h.sign_in(alice()).await;
    let viewer = h.sign_in(bob()).await;

    // Only admins create projects.
    let denied = h
        .write(
            &viewer,
            Method::POST,
            "/api/v1/projects",
            json!({"slug": "prod", "name": "Production"}),
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.json["error"], "forbidden");
    for (slug, name) in [("prod", "Production"), ("dev", "Development")] {
        let created = h
            .write(
                &admin,
                Method::POST,
                "/api/v1/projects",
                json!({"slug": slug, "name": name}),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json);
        assert_eq!(created.json["slug"], slug);
    }
    let duplicate = h
        .write(
            &admin,
            Method::POST,
            "/api/v1/projects",
            json!({"slug": "prod", "name": "Again"}),
        )
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    let invalid = h
        .write(
            &admin,
            Method::POST,
            "/api/v1/projects",
            json!({"slug": "Not Valid", "name": "x"}),
        )
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Admins see everything; a user without roles sees nothing.
    let all = h.get(&admin, "/api/v1/projects").await;
    let slugs: Vec<&str> = all.json["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, ["dev", "prod"]);
    let none = h.get(&viewer, "/api/v1/projects").await;
    assert_eq!(none.status, StatusCode::OK);
    assert_eq!(none.json["projects"], json!([]));
    assert_eq!(
        h.get(&viewer, "/api/v1/projects/prod").await.status,
        StatusCode::NOT_FOUND
    );

    // The admin finds Bob and grants him viewer on prod.
    assert_eq!(
        h.get(&viewer, "/api/v1/users").await.status,
        StatusCode::FORBIDDEN
    );
    let users = h.get(&admin, "/api/v1/users").await;
    let bob_id = users.json["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["subject"] == "bob")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let members_uri = format!("/api/v1/projects/prod/members/{bob_id}");
    let granted = h
        .write(&admin, Method::PUT, &members_uri, json!({"role": "viewer"}))
        .await;
    assert_eq!(granted.status, StatusCode::OK, "{:?}", granted.json);
    assert_eq!(granted.json["role"], "viewer");
    assert_eq!(granted.json["user"]["email"], "bob@example.com");

    let visible = h.get(&viewer, "/api/v1/projects").await;
    let projects = visible.json["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0]["slug"], "prod");
    assert_eq!(projects[0]["role"], "viewer");
    assert_eq!(
        projects[0]["permissions"],
        json!({"view": true, "operate": false, "manage_members": false})
    );
    assert_eq!(
        h.get(&viewer, "/api/v1/projects/prod").await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.get(&viewer, "/api/v1/projects/dev").await.status,
        StatusCode::NOT_FOUND
    );
    let members = h.get(&viewer, "/api/v1/projects/prod/members").await;
    assert_eq!(members.status, StatusCode::OK);
    assert_eq!(members.json["members"][0]["role"], "viewer");

    // A viewer cannot manage members, even of a project they can see.
    let escalate = h
        .write(
            &viewer,
            Method::PUT,
            &members_uri,
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(escalate.status, StatusCode::FORBIDDEN);

    // Promote, then remove.
    let promoted = h
        .write(
            &admin,
            Method::PUT,
            &members_uri,
            json!({"role": "operator"}),
        )
        .await;
    assert_eq!(promoted.json["role"], "operator");
    let operator_view = h.get(&viewer, "/api/v1/projects/prod").await;
    assert_eq!(operator_view.json["permissions"]["operate"], true);
    let removed = h
        .write(&admin, Method::DELETE, &members_uri, Value::Null)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get(&viewer, "/api/v1/projects/prod").await.status,
        StatusCode::NOT_FOUND
    );

    // Unknown users and malformed bodies are rejected with JSON errors.
    let unknown = h
        .write(
            &admin,
            Method::PUT,
            "/api/v1/projects/prod/members/00000000-0000-0000-0000-000000000000",
            json!({"role": "viewer"}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let bad_role = h
        .write(&admin, Method::PUT, &members_uri, json!({"role": "admin"}))
        .await;
    assert_eq!(bad_role.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad_role.json["error"], "invalid_request");

    let assignments: Vec<(String, Value)> = sqlx::query_as(
        "SELECT action, details FROM audit_events WHERE action LIKE 'project.%' ORDER BY id",
    )
    .fetch_all(&h.db.pool)
    .await
    .unwrap();
    let actions: Vec<&str> = assignments.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "project.create",
            "project.create",
            "project.role_assign",
            "project.role_assign",
            "project.role_remove"
        ]
    );
    assert_eq!(
        assignments[3].1,
        json!({"role": "operator", "previous_role": "viewer"})
    );

    h.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_role_changes_keep_the_audit_chain_accurate() {
    let h = harness!(Harness::start());
    let admin = h.sign_in(alice()).await;
    h.sign_in(bob()).await;
    let created = h
        .write(
            &admin,
            Method::POST,
            "/api/v1/projects",
            json!({"slug": "prod", "name": "Production"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let bob_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE subject = 'bob'")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();

    // Several first assignments race for a (project, user) pair with no role yet.
    let uri = format!("/api/v1/projects/prod/members/{bob_id}");
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..8 {
        let role = if i % 2 == 0 { "viewer" } else { "operator" };
        let request = write_request(&admin, Method::PUT, &uri, json!({ "role": role }));
        let app = h.app.clone();
        tasks.spawn(async move { app.oneshot(request).await.unwrap().status() });
    }
    while let Some(status) = tasks.join_next().await {
        assert_eq!(status.unwrap(), StatusCode::OK);
    }

    let details: Vec<Value> = sqlx::query_scalar(
        "SELECT details FROM audit_events \
         WHERE action = 'project.role_assign' AND target_user_id = $1 ORDER BY id",
    )
    .bind(bob_id)
    .fetch_all(&h.db.pool)
    .await
    .unwrap();
    assert_eq!(details.len(), 8);
    assert_eq!(details[0]["previous_role"], Value::Null, "{details:?}");
    for pair in details.windows(2) {
        assert_eq!(pair[1]["previous_role"], pair[0]["role"], "{details:?}");
    }
    let current: String =
        sqlx::query_scalar("SELECT role FROM project_role_assignments WHERE user_id = $1")
            .bind(bob_id)
            .fetch_one(&h.db.pool)
            .await
            .unwrap();
    assert_eq!(details[7]["role"], current.as_str());

    h.finish().await;
}

#[tokio::test]
async fn state_changes_need_the_public_origin() {
    let h = harness!(Harness::start());
    let admin = h.sign_in(alice()).await;
    let request = Request::post("/api/v1/projects")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={admin}"))
        .header(header::ORIGIN, "https://vn.example.com.evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"slug":"prod","name":"Production"}"#))
        .unwrap();
    let response = h.send(request).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.json["error"], "csrf_rejected");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
        .fetch_one(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    h.finish().await;
}

#[tokio::test]
async fn return_to_outside_the_site_falls_back_to_root() {
    let h = harness!(Harness::start());
    let login = h.start_login("https://evil.example").await;
    let (code, state) = h.provider.authorize(&login.location, alice());
    let callback = h.callback(&code, &state, Some(&login.login_cookie)).await;
    assert_eq!(callback.location(), "/");
    h.finish().await;
}
