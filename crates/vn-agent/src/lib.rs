//! Vanguard Nexus agent: enrollment, identity storage, the authenticated outbound
//! connection to the server, and cluster inventory collection.
//!
//! The binary in `main.rs` wires these together: load the identity (or enroll with
//! `VN_ENROLLMENT_TOKEN`), then hand it to a [`runner::Runner`], which keeps one
//! WebSocket connection open and reconnects with backoff. Each connection starts the
//! [`collect::KubeCollector`] watchers afresh and sends their snapshots and watch
//! events through a [`queue::SyncQueue`] within the server's acknowledgement window.

pub mod backoff;
pub mod client;
pub mod cluster;
pub mod collect;
pub mod connection;
pub mod enroll;
pub mod identity;
pub mod queue;
pub mod runner;

/// Version reported at enrollment and in `hello`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
