//! `vn`: command-line client for Vanguard Nexus.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use vn_config::Config;
use vn_core::{DatabaseStatus, HealthResponse, HealthStatus};

/// Vanguard Nexus command-line client.
#[derive(Debug, Parser)]
#[command(name = "vn", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check a server's health endpoint. Exits non-zero unless the server reports ok.
    Health {
        /// Server base URL, for example http://localhost:8080.
        #[arg(long, env = "VN_SERVER_URL")]
        server: String,
    },
    /// Work with configuration files.
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Parse and validate a config file.
    Validate {
        /// Path to the YAML config file.
        path: PathBuf,
        /// Also require the database URL environment variable to be set.
        #[arg(long)]
        check_env: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Health { server } => health(&server).await,
        Command::Config(ConfigCommand::Validate { path, check_env }) => {
            validate_config(&path, check_env)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn health(server: &str) -> anyhow::Result<()> {
    let health = fetch_health(server).await?;
    println!("status:   {}", status_label(health.status));
    println!("version:  {}", health.version);
    println!("database: {}", database_label(health.database));
    if health.status != HealthStatus::Ok {
        bail!("server at {server} is not healthy");
    }
    Ok(())
}

/// Calls the health endpoint. A 503 still carries a health body, so the body is parsed
/// regardless of status and the caller decides from `status`.
async fn fetch_health(server: &str) -> anyhow::Result<HealthResponse> {
    let url = health_url(server)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("request to {url} failed"))?;
    let code = response.status();
    response
        .json::<HealthResponse>()
        .await
        .with_context(|| format!("{url} returned HTTP {code} without a valid health response"))
}

fn health_url(server: &str) -> anyhow::Result<reqwest::Url> {
    let base =
        reqwest::Url::parse(server).with_context(|| format!("invalid server URL `{server}`"))?;
    if !matches!(base.scheme(), "http" | "https") {
        bail!("server URL must use http or https, got `{server}`");
    }
    let url = format!(
        "{}{}",
        base.as_str().trim_end_matches('/'),
        vn_core::HEALTH_PATH
    );
    Ok(reqwest::Url::parse(&url)?)
}

fn validate_config(path: &std::path::Path, check_env: bool) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    if check_env {
        config.database.resolve_url()?;
    }
    println!("{}: valid (version {})", path.display(), config.version);
    Ok(())
}

fn status_label(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Ok => "ok",
        HealthStatus::Degraded => "degraded",
    }
}

fn database_label(status: DatabaseStatus) -> &'static str {
    match status {
        DatabaseStatus::Ok => "ok",
        DatabaseStatus::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vn_server::{AppState, DatabaseHealth, PingFuture};

    struct FakeDatabase(bool);

    impl DatabaseHealth for FakeDatabase {
        fn ping(&self) -> PingFuture<'_> {
            let up = self.0;
            Box::pin(async move { if up { Ok(()) } else { Err("down".into()) } })
        }
    }

    async fn serve(database_up: bool) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = vn_server::router(AppState::new(FakeDatabase(database_up)), None);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[test]
    fn builds_health_url() {
        for base in ["http://vn:8080", "http://vn:8080/"] {
            assert_eq!(
                health_url(base).unwrap().as_str(),
                "http://vn:8080/api/v1/health"
            );
        }
        assert_eq!(
            health_url("https://example.com/vn/").unwrap().as_str(),
            "https://example.com/vn/api/v1/health"
        );
        assert!(health_url("vn:8080").is_err());
        assert!(health_url("not a url").is_err());
    }

    #[tokio::test]
    async fn health_succeeds_against_healthy_server() {
        let server = serve(true).await;
        let health = fetch_health(&server).await.unwrap();
        assert_eq!(health.status, HealthStatus::Ok);
        assert_eq!(health.database, DatabaseStatus::Ok);
        super::health(&server).await.unwrap();
    }

    #[tokio::test]
    async fn health_fails_when_server_is_degraded() {
        let server = serve(false).await;
        let health = fetch_health(&server).await.unwrap();
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(health.database, DatabaseStatus::Unavailable);
        assert!(super::health(&server).await.is_err());
    }

    #[tokio::test]
    async fn health_fails_for_non_health_response() {
        let server = serve(true).await;
        let err = fetch_health(&format!("{server}/elsewhere"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("HTTP 404"), "{err:#}");
    }
}
