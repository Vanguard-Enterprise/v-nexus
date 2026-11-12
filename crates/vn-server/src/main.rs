use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use vn_config::Config;

/// Upper bound on closing the database pool during shutdown.
const POOL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Vanguard Nexus server.
#[derive(Debug, Parser)]
#[command(name = "vn-server", version, about)]
struct Args {
    /// Path to the YAML config file.
    #[arg(long, env = vn_config::CONFIG_PATH_ENV, default_value = vn_config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    // sqlx logs unrecognized connection URL parameters with their values. vn-config rejects
    // those before connecting, and this keeps any that slip through out of the logs.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into())
        .add_directive(
            "sqlx_postgres::options::parse=off"
                .parse()
                .expect("static log directive is valid"),
        );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let config = Config::load(&args.config)?;
    tracing::info!(path = %args.config.display(), "loaded config");

    let url = config.database.resolve_url()?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url.expose())
        .await
        .context("failed to connect to PostgreSQL")?;

    vn_server::MIGRATOR
        .run(&pool)
        .await
        .context("failed to run database migrations")?;
    tracing::info!("database migrations are up to date");

    let static_dir = config.server.static_dir.filter(|dir| {
        let present = dir.is_dir();
        if !present {
            tracing::warn!(path = %dir.display(), "static_dir does not exist; UI routes will return 404");
        }
        present
    });

    let mut state = vn_server::AppState::new(pool.clone());
    match &config.auth {
        Some(auth) => {
            let secret = auth.resolve_client_secret()?;
            state = state.with_auth(
                vn_server::AuthService::new(auth, &secret).context("invalid `auth` settings")?,
            );
            tracing::info!(
                issuer = %auth.issuer_url,
                public_url = %auth.public_origin(),
                "OIDC sign-in enabled"
            );
            if !auth.is_https() {
                tracing::warn!(
                    "auth.public_url uses http, so session cookies are not marked Secure; \
                     use https outside local development"
                );
            }
        }
        None => tracing::warn!(
            "config has no `auth` section: sign-in is disabled and every API route \
             except health answers 401"
        ),
    }

    let app = vn_server::router(state, static_dir.as_deref());
    let listener = TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    tracing::info!(addr = %listener.local_addr()?, version = vn_server::VERSION, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    // Closing waits for checked-out connections. Bound it so a stalled database cannot
    // block shutdown indefinitely.
    if tokio::time::timeout(POOL_CLOSE_TIMEOUT, pool.close())
        .await
        .is_err()
    {
        tracing::warn!(timeout = ?POOL_CLOSE_TIMEOUT, "timed out closing database connections");
    }
    tracing::info!("shut down cleanly");
    Ok(())
}

/// Resolves on SIGINT (Ctrl+C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
