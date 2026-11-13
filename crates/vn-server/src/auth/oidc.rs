//! OpenID Connect authorization code flow with PKCE, built on the `openidconnect` crate.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AsyncHttpClient, AuthenticationFlow, AuthorizationCode,
    ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, IdTokenFields,
    IssuerUrl, JwsSigningAlgorithm, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, SignatureVerificationError,
    StandardErrorResponse, StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use vn_config::{AdminMapping, AuthConfig, SUBJECT_CLAIM, Secret};

/// How long discovered provider metadata and signing keys are reused before they are
/// fetched again, so key rotation at the provider is picked up. An ID token signed with a
/// key missing from the cached set also triggers a fetch; see [`Oidc::refresh`].
const DISCOVERY_TTL: Duration = Duration::from_secs(15 * 60);

/// Time limit for each request to the provider.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest provider response accepted.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Longest values stored for informational profile claims.
const MAX_EMAIL_CHARS: usize = 320;
const MAX_NAME_CHARS: usize = 200;

/// Every claim not covered by the standard set, so a custom admin claim can be read
/// whatever its name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct ExtraClaims {
    #[serde(flatten)]
    claims: serde_json::Map<String, serde_json::Value>,
}

impl AdditionalClaims for ExtraClaims {}

type TokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type OidcTokenResponse = StandardTokenResponse<TokenFields, CoreTokenType>;

type OidcClient = openidconnect::Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OidcTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Failures talking to the provider or validating its answers. Messages never include
/// tokens, codes, or the client secret.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OidcError {
    #[error("invalid OIDC setting: {0}")]
    Setup(String),
    #[error("provider discovery failed: {0}")]
    Discovery(String),
    #[error("token exchange failed: {0}")]
    TokenExchange(String),
    #[error("provider did not return an ID token")]
    MissingIdToken,
    #[error("ID token rejected: {0}")]
    IdToken(String),
}

/// The authenticated identity extracted from a verified ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) email: Option<String>,
    pub(crate) display_name: Option<String>,
    pub(crate) installation_admin: bool,
}

/// What the browser must be sent to, and what must be remembered for the callback.
pub(crate) struct AuthorizationStart {
    pub(crate) url: url::Url,
    pub(crate) state: String,
    pub(crate) nonce: String,
    pub(crate) pkce_verifier: String,
}

pub(crate) struct Oidc {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
    scopes: Vec<Scope>,
    admin: AdminMapping,
    http: HttpClient,
    cached: Mutex<Option<(Instant, Arc<OidcClient>)>>,
}

impl Oidc {
    pub(crate) fn new(config: &AuthConfig, client_secret: &Secret) -> Result<Self, OidcError> {
        let issuer = IssuerUrl::new(config.issuer_url.clone())
            .map_err(|err| OidcError::Setup(format!("auth.issuer_url: {err}")))?;
        let redirect_url = RedirectUrl::new(config.redirect_url())
            .map_err(|err| OidcError::Setup(format!("auth.public_url: {err}")))?;
        let scopes = config
            .scopes
            .iter()
            // The crate always requests `openid`.
            .filter(|scope| *scope != "openid")
            .map(|scope| Scope::new(scope.clone()))
            .collect();
        Ok(Self {
            issuer,
            client_id: ClientId::new(config.client_id.clone()),
            client_secret: ClientSecret::new(client_secret.expose().to_owned()),
            redirect_url,
            scopes,
            admin: config.admin.clone(),
            http: HttpClient::new().map_err(|err| OidcError::Setup(err.to_string()))?,
            cached: Mutex::new(None),
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        self.issuer.as_str()
    }

    /// Returns a client built from discovered metadata, discovering again when the cached
    /// copy is older than [`DISCOVERY_TTL`].
    async fn client(&self) -> Result<Arc<OidcClient>, OidcError> {
        let mut cached = self.cached.lock().await;
        if let Some((fetched, client)) = cached.as_ref()
            && fetched.elapsed() < DISCOVERY_TTL
        {
            return Ok(client.clone());
        }
        self.discover(&mut cached).await
    }

    /// Discovers again because `stale` lacked the key an ID token was signed with, unless
    /// the cache already holds a newer client. Concurrent callbacks that hit the same
    /// rotation therefore share one fetch.
    async fn refresh(&self, stale: &Arc<OidcClient>) -> Result<Arc<OidcClient>, OidcError> {
        let mut cached = self.cached.lock().await;
        if let Some((_, client)) = cached.as_ref()
            && !Arc::ptr_eq(client, stale)
        {
            return Ok(client.clone());
        }
        self.discover(&mut cached).await
    }

    /// Fetches provider metadata and signing keys and stores the resulting client.
    async fn discover(
        &self,
        cached: &mut Option<(Instant, Arc<OidcClient>)>,
    ) -> Result<Arc<OidcClient>, OidcError> {
        let metadata = CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http)
            .await
            .map_err(|err| OidcError::Discovery(error_chain(&err)))?;
        let client = OidcClient::from_provider_metadata(
            metadata,
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_url.clone());
        let client = Arc::new(client);
        *cached = Some((Instant::now(), client.clone()));
        Ok(client)
    }

    /// Builds the provider authorization URL with fresh state, nonce, and PKCE challenge.
    pub(crate) async fn start(&self) -> Result<AuthorizationStart, OidcError> {
        let client = self.client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(self.scopes.iter().cloned())
            .set_pkce_challenge(challenge)
            .url();
        Ok(AuthorizationStart {
            url,
            state: state.into_secret(),
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.into_secret(),
        })
    }

    /// Redeems an authorization code and verifies the ID token against the nonce sent with
    /// the matching authorization request.
    pub(crate) async fn finish(
        &self,
        code: String,
        pkce_verifier: String,
        nonce: &str,
    ) -> Result<Identity, OidcError> {
        let client = self.client().await?;
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|err| OidcError::TokenExchange(err.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|err| OidcError::TokenExchange(describe_token_error(&err)))?;

        let id_token = token.id_token().ok_or(OidcError::MissingIdToken)?;
        // Read from the unverified header, which is safe because it can only refuse a token.
        // Shared-secret algorithms would tie ID token integrity to the client secret.
        let alg = id_token
            .signing_alg()
            .map_err(|err| OidcError::IdToken(err.to_string()))?;
        if alg.uses_shared_secret() {
            return Err(OidcError::IdToken(
                "ID token is signed with a shared-secret algorithm (HS256/HS384/HS512). \
                 Vanguard Nexus accepts only asymmetric ID token signatures (RS*, PS*, ES*, \
                 EdDSA); configure the provider to sign ID tokens with RS256."
                    .into(),
            ));
        }

        let nonce = Nonce::new(nonce.to_owned());
        let first = id_token.claims(&client.id_token_verifier(), &nonce);
        let (client, claims) = match first {
            // The provider may have rotated its signing key since the keys were cached.
            // Verify the same ID token again with fresh keys; the code is already redeemed.
            Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey,
            )) => {
                tracing::info!("ID token signed with an unknown key; fetching provider keys");
                let client = self.refresh(&client).await?;
                let claims = id_token
                    .claims(&client.id_token_verifier(), &nonce)
                    .map_err(|err| OidcError::IdToken(err.to_string()))?;
                (client, claims)
            }
            other => (
                client,
                other.map_err(|err| OidcError::IdToken(err.to_string()))?,
            ),
        };

        if let Some(expected) = claims.access_token_hash() {
            let verifier = client.id_token_verifier();
            let key = id_token
                .signing_key(&verifier)
                .map_err(|err| OidcError::IdToken(err.to_string()))?;
            let actual = AccessTokenHash::from_token(token.access_token(), alg, key)
                .map_err(|err| OidcError::IdToken(err.to_string()))?;
            if actual != *expected {
                return Err(OidcError::IdToken("access token hash mismatch".into()));
            }
        }

        let subject = claims.subject().clone();
        // The client parses `sub` into a dedicated field, so it never appears among the
        // additional claims. Config validation rejects the other standard claims.
        let mut installation_admin = if self.admin.claim == SUBJECT_CLAIM {
            Some(self.admin.values.iter().any(|v| v == subject.as_str()))
        } else {
            claims
                .additional_claims()
                .claims
                .get(&self.admin.claim)
                .map(|value| claim_grants(value, &self.admin.values))
        };

        // Some providers (Zitadel by default) put role claims only in the userinfo response.
        if installation_admin.is_none()
            && let Ok(request) =
                client.user_info(token.access_token().clone(), Some(subject.clone()))
        {
            match request
                .request_async::<ExtraClaims, _, CoreGenderClaim>(&self.http)
                .await
            {
                Ok(info) => {
                    installation_admin = info
                        .additional_claims()
                        .claims
                        .get(&self.admin.claim)
                        .map(|value| claim_grants(value, &self.admin.values));
                }
                Err(err) => {
                    // Only the top-level message: parse errors can quote claim values.
                    tracing::warn!(
                        error = %err,
                        "userinfo request failed; signing in without the admin role"
                    );
                }
            }
        }

        let email = claims
            .email()
            .map(|email| truncate(email.as_str(), MAX_EMAIL_CHARS));
        let display_name = claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str())
            .or_else(|| claims.preferred_username().map(|name| name.as_str()))
            .map(|name| truncate(name, MAX_NAME_CHARS));

        Ok(Identity {
            issuer: claims.issuer().as_str().to_owned(),
            subject: subject.as_str().to_owned(),
            email,
            display_name,
            installation_admin: installation_admin.unwrap_or(false),
        })
    }
}

/// Whether a claim value contains any of `wanted`. Accepts a string, a list of strings
/// (groups), or an object keyed by role name (Zitadel project roles).
pub(crate) fn claim_grants(value: &serde_json::Value, wanted: &[String]) -> bool {
    use serde_json::Value;
    let wanted = |candidate: &str| wanted.iter().any(|w| w == candidate);
    match value {
        Value::String(s) => wanted(s),
        Value::Array(items) => items.iter().any(|item| item.as_str().is_some_and(wanted)),
        Value::Object(map) => map.keys().any(|key| wanted(key)),
        _ => false,
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

/// Describes a failed token request without anything from a successful response body:
/// parse errors quote JSON values, which could include tokens.
fn describe_token_error<RE, T>(err: &RequestTokenError<RE, T>) -> String
where
    RE: std::error::Error + 'static,
    T: openidconnect::ErrorResponse + 'static,
{
    match err {
        RequestTokenError::Parse(..) => {
            "provider sent a token response that could not be parsed".to_owned()
        }
        // Network failures (endpoint and cause) and the provider's own OAuth error answer.
        RequestTokenError::Request(_)
        | RequestTokenError::ServerResponse(_)
        | RequestTokenError::Other(_) => error_chain(err),
    }
}

/// Formats an error with its sources. Use it only for errors that describe endpoints and
/// status codes, not response bodies.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// HTTP client for provider requests. Redirects are disabled (following them would allow
/// SSRF through a hostile discovery document) and response bodies are size-limited.
#[derive(Clone)]
struct HttpClient(reqwest::Client);

impl HttpClient {
    fn new() -> reqwest::Result<Self> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PROVIDER_TIMEOUT)
            .build()
            .map(Self)
    }
}

#[derive(Debug, thiserror::Error)]
enum HttpError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error("invalid HTTP response: {0}")]
    Response(#[from] axum::http::Error),
    #[error("response body exceeds {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
}

impl<'c> AsyncHttpClient<'c> for HttpClient {
    type Error = HttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request = reqwest::Request::try_from(request)?;
            let mut response = self.0.execute(request).await?;
            let mut builder = axum::http::Response::builder().status(response.status());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err(HttpError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(builder.body(body)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn wanted() -> Vec<String> {
        vec!["vn-admin".into(), "platform".into()]
    }

    #[test]
    fn string_claim_must_match_exactly() {
        assert!(claim_grants(&json!("vn-admin"), &wanted()));
        assert!(!claim_grants(&json!("vn-admins"), &wanted()));
    }

    #[test]
    fn list_claim_matches_any_member() {
        assert!(claim_grants(&json!(["users", "platform"]), &wanted()));
        assert!(!claim_grants(&json!(["users", 1, null]), &wanted()));
    }

    #[test]
    fn object_claim_matches_keys_not_values() {
        let zitadel = json!({"vn-admin": {"123": "acme.zitadel.cloud"}});
        assert!(claim_grants(&zitadel, &wanted()));
        assert!(!claim_grants(&json!({"viewer": "vn-admin"}), &wanted()));
    }

    #[test]
    fn other_claim_types_never_match() {
        assert!(!claim_grants(&json!(true), &wanted()));
        assert!(!claim_grants(&json!(null), &wanted()));
    }

    #[test]
    fn truncates_by_characters() {
        assert_eq!(truncate("ééé", 2), "éé");
    }
}
