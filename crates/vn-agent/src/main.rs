//! Vanguard Nexus agent. Enrollment and inventory collection arrive in later milestones;
//! for now this only parses its settings and exits.

use std::io::IsTerminal;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Vanguard Nexus agent.
#[derive(Debug, Parser)]
#[command(name = "vn-agent", version, about)]
struct Args {
    /// Base URL of the Vanguard Nexus server the agent connects to.
    #[arg(long, env = "VN_SERVER_URL")]
    server_url: Option<String>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let args = Args::parse();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        server_url = args.server_url.as_deref().unwrap_or("<unset>"),
        "vn-agent started"
    );
    tracing::info!("agent is not implemented yet; exiting");
}
