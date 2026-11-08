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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
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

    let app = vn_server::router(
        vn_server::AppState::new(pool.clone()),
        static_dir.as_deref(),
    );
    let listener = TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    tracing::info!(addr = %listener.local_addr()?, version = vn_server::VERSION, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    pool.close().await;
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
