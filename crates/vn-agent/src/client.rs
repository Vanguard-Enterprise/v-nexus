//! HTTP calls to the server: server information, enrollment, and session setup.

use std::time::Duration;

use anyhow::{Context, bail};
use reqwest::StatusCode;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;
use uuid::Uuid;
use vn_core::{
    AGENT_CHALLENGE_PATH, AGENT_CONNECT_PATH, AGENT_ENROLL_PATH, AGENT_INFO_PATH, AgentServerInfo,
    AgentSession, ApiError, Challenge, ChallengeRequest, EnrollRequest, EnrollResponse,
    SessionRequest,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A failed call.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The request did not complete: the server is unreachable, slow, or answered
    /// something that is not the expected JSON.
    #[error("request to {path} failed: {source}")]
    Transport {
        path: &'static str,
        #[source]
        source: reqwest::Error,
    },
    /// The server answered with an API error.
    #[error("{path} answered {status}: {} ({})", .error.message, .error.error)]
    Api {
        path: &'static str,
        status: StatusCode,
        error: ApiError,
    },
}

impl CallError {
    /// The API error code, such as `agent_revoked`.
    pub fn code(&self) -> Option<&str> {
        match self {
            CallError::Api { error, .. } => Some(&error.error),
            CallError::Transport { .. } => None,
        }
    }

    /// Whether trying again later can help: the request did not reach a decision, or
    /// the server is overloaded or failing.
    pub fn is_transient(&self) -> bool {
        match self {
            CallError::Transport { .. } => true,
            CallError::Api { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
        }
    }
}

/// The server's agent endpoints.
#[derive(Debug, Clone)]
pub struct ServerClient {
    http: reqwest::Client,
    /// The server URL, ending with `/`.
    base: Url,
}

impl ServerClient {
    /// A client for the server at `server_url` (`https://`, or `http://` for
    /// development). A path prefix is kept, for servers behind a path-routing proxy.
    pub fn new(server_url: &str) -> anyhow::Result<Self> {
        let mut base = Url::parse(server_url.trim()).context("the server URL is not a URL")?;
        if !matches!(base.scheme(), "http" | "https") {
            bail!("the server URL must use https (or http for development)");
        }
        if base.query().is_some() || base.fragment().is_some() || !base.username().is_empty() {
            bail!("the server URL must not have a query, fragment, or credentials");
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("vn-agent/", env!("CARGO_PKG_VERSION")))
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("failed to build the HTTP client")?;
        Ok(Self { http, base })
    }

    /// The server URL as given, normalized.
    pub fn base(&self) -> &Url {
        &self.base
    }

    fn url(&self, path: &str) -> Url {
        self.base
            .join(path.trim_start_matches('/'))
            .expect("API paths are relative URLs")
    }

    /// The WebSocket URL of the connect endpoint: `wss://` for an https server.
    pub fn connect_url(&self) -> Url {
        let mut url = self.url(AGENT_CONNECT_PATH);
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .expect("ws and wss are valid schemes");
        url
    }

    pub async fn info(&self) -> Result<AgentServerInfo, CallError> {
        let request = self.http.get(self.url(AGENT_INFO_PATH));
        send(AGENT_INFO_PATH, request).await
    }

    pub async fn enroll(&self, body: &EnrollRequest) -> Result<EnrollResponse, CallError> {
        self.post(AGENT_ENROLL_PATH, body).await
    }

    pub async fn challenge(&self, agent_id: Uuid) -> Result<Challenge, CallError> {
        self.post(AGENT_CHALLENGE_PATH, &ChallengeRequest { agent_id })
            .await
    }

    pub async fn session(&self, body: &SessionRequest) -> Result<AgentSession, CallError> {
        self.post(vn_core::AGENT_SESSION_PATH, body).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &'static str,
        body: &B,
    ) -> Result<T, CallError> {
        send(path, self.http.post(self.url(path)).json(body)).await
    }
}

async fn send<T: DeserializeOwned>(
    path: &'static str,
    request: reqwest::RequestBuilder,
) -> Result<T, CallError> {
    let transport = |source| CallError::Transport { path, source };
    let response = request.send().await.map_err(transport)?;
    let status = response.status();
    if status.is_success() {
        return response.json().await.map_err(transport);
    }
    let error = match response.json::<ApiError>().await {
        Ok(error) => error,
        Err(_) => ApiError::new(
            "unknown",
            format!("HTTP {status} without an API error body"),
        ),
    };
    Err(CallError::Api {
        path,
        status,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_keep_a_path_prefix_and_map_to_websocket_schemes() {
        let client = ServerClient::new("https://vn.example.com").unwrap();
        assert_eq!(
            client.url(AGENT_INFO_PATH).as_str(),
            "https://vn.example.com/api/v1/agent/info"
        );
        assert_eq!(
            client.connect_url().as_str(),
            "wss://vn.example.com/api/v1/agent/connect"
        );
        let prefixed = ServerClient::new("http://10.0.0.1:8080/vn").unwrap();
        assert_eq!(
            prefixed.connect_url().as_str(),
            "ws://10.0.0.1:8080/vn/api/v1/agent/connect"
        );
    }

    #[test]
    fn rejects_unusable_server_urls() {
        for bad in [
            "vn.example.com",
            "ftp://vn.example.com",
            "https://vn.example.com/?x=1",
            "https://user:pw@vn.example.com",
        ] {
            assert!(ServerClient::new(bad).is_err(), "{bad}");
        }
    }
}
