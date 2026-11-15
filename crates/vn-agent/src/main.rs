//! Vanguard Nexus agent.
//!
//! Loads its identity, enrolling first with `VN_ENROLLMENT_TOKEN` when none is stored,
//! then keeps an authenticated WebSocket connection to the server, reconnecting with
//! backoff. It exits with status 2 when the server revokes it or rejects its identity,
//! because only re-enrollment can fix either.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use vn_agent::backoff::Backoff;
use vn_agent::client::ServerClient;
use vn_agent::identity::{Identity, IdentityStore};
use vn_agent::runner::{self, Runner, Stop};
use vn_agent::{cluster, enroll};

/// Environment variable holding the enrollment token. It is read from the environment
/// only, never from the command line, where other processes could see it.
const ENROLLMENT_TOKEN_ENV: &str = "VN_ENROLLMENT_TOKEN";

/// Exit status when the agent needs to be enrolled again.
const EXIT_REENROLL: u8 = 2;

/// Vanguard Nexus agent.
#[derive(Debug, Parser)]
#[command(
    name = "vn-agent",
    version,
    about,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the agent (the default).
    Run(RunArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Base URL of the Vanguard Nexus server, for example `https://vn.example.com`.
    #[arg(long, env = "VN_SERVER_URL")]
    server_url: Option<String>,
    /// Identity file, used when not running in Kubernetes (`POD_NAMESPACE` unset).
    #[arg(long, env = "VN_AGENT_IDENTITY_FILE")]
    identity_file: Option<PathBuf>,
    /// Namespace the agent runs in, set through the downward API. When set, the identity
    /// is kept in the Secret `vn-agent-identity` there.
    #[arg(long, env = "POD_NAMESPACE")]
    pod_namespace: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(std::io::stdout().is_terminal())
        .init();
    let cli = Cli::parse();
    let args = match cli.command {
        Some(Command::Run(args)) => args,
        None => cli.run,
    };
    match run(args).await {
        Ok(Stop::Shutdown) => {
            tracing::info!("vn-agent stopped");
            ExitCode::SUCCESS
        }
        Ok(Stop::Revoked) => {
            tracing::error!(
                "the server revoked this agent; it will not reconnect. To re-enroll, delete \
                 the stored identity and restart the agent with a new enrollment token"
            );
            ExitCode::from(EXIT_REENROLL)
        }
        Ok(Stop::IdentityMismatch(reason)) => {
            tracing::error!(
                reason,
                "the server rejected this agent's identity; it will not reconnect. An agent \
                 identity belongs to one cluster: enroll a new agent for this cluster"
            );
            ExitCode::from(EXIT_REENROLL)
        }
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<Stop> {
    // kube and reqwest both use rustls with aws-lc-rs; make it the process default.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let Some(server_url) = args.server_url else {
        bail!("set VN_SERVER_URL (or --server-url) to the Vanguard Nexus server URL");
    };
    let server = ServerClient::new(&server_url).context("invalid VN_SERVER_URL")?;
    tracing::info!(
        version = vn_agent::VERSION,
        server = %server.base(),
        "vn-agent starting"
    );

    let (stop_tx, stop) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });

    let kube = cluster::client().await?;
    let store = match (&args.pod_namespace, args.identity_file) {
        (Some(namespace), _) if !namespace.is_empty() => {
            IdentityStore::secret(kube.clone(), namespace)
        }
        (_, Some(path)) => IdentityStore::File(path),
        _ => bail!(
            "set VN_AGENT_IDENTITY_FILE (or --identity-file) when not running in Kubernetes \
             (POD_NAMESPACE is unset)"
        ),
    };
    let cluster = cluster::info(&kube).await?;
    tracing::info!(
        fingerprint = %cluster.fingerprint,
        kubernetes_version = cluster.kubernetes_version.as_deref().unwrap_or("unknown"),
        "read cluster identity"
    );

    let identity = match store.load().await? {
        Some(identity) => {
            tracing::info!(agent_id = %identity.agent_id, store = %store, "loaded agent identity");
            identity
        }
        None => {
            match enroll_with_retries(&server, &store, &cluster.fingerprint, stop.clone()).await? {
                Some(identity) => identity,
                None => return Ok(Stop::Shutdown),
            }
        }
    };
    if identity.server_url.trim_end_matches('/') != server.base().as_str().trim_end_matches('/') {
        tracing::warn!(
            enrolled_with = %identity.server_url,
            "VN_SERVER_URL differs from the server this agent enrolled with; using VN_SERVER_URL"
        );
    }
    Ok(Runner::new(server, identity, cluster)?.run(stop).await)
}

/// Enrolls and stores the identity, retrying while the server is unreachable or
/// failing. Returns `None` when shutdown is requested first.
async fn enroll_with_retries(
    server: &ServerClient,
    store: &IdentityStore,
    fingerprint: &str,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<Option<Identity>> {
    let token = match std::env::var(ENROLLMENT_TOKEN_ENV) {
        Ok(token) if !token.trim().is_empty() => token.trim().to_owned(),
        _ => bail!(
            "no agent identity is stored in {store}, and {ENROLLMENT_TOKEN_ENV} is not set; \
             create an enrollment token in Vanguard Nexus and pass it in {ENROLLMENT_TOKEN_ENV}"
        ),
    };
    // One key for every attempt, so a retry after a lost response is recognized as a
    // repeat of the committed enrollment instead of a second use of the token.
    let key = enroll::generate_key()?;
    let mut backoff = Backoff::default();
    loop {
        match enroll::enroll(server, &token, &key, fingerprint).await {
            Ok(identity) => {
                store.create(&identity).await.with_context(|| {
                    format!(
                        "agent {} enrolled, but its identity could not be stored; delete the \
                         agent in Vanguard Nexus and enroll again with a new token",
                        identity.agent_id
                    )
                })?;
                tracing::info!(agent_id = %identity.agent_id, store = %store, "agent enrolled");
                return Ok(Some(identity));
            }
            Err(err) => {
                let transient = err
                    .downcast_ref::<vn_agent::client::CallError>()
                    .is_some_and(|err| err.is_transient());
                if !transient {
                    return Err(err.context("enrollment failed"));
                }
                tracing::warn!(error = %err, "enrollment failed; retrying");
                if !runner::wait(backoff.next_delay(), &mut stop).await {
                    return Ok(None);
                }
            }
        }
    }
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
    tracing::info!("shutdown signal received");
}
