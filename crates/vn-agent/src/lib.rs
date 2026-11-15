//! Vanguard Nexus agent: enrollment, identity storage, and the authenticated outbound
//! connection to the server.
//!
//! The binary in `main.rs` wires these together: load the identity (or enroll with
//! `VN_ENROLLMENT_TOKEN`), then hand it to a [`runner::Runner`], which keeps one
//! WebSocket connection open and reconnects with backoff.

pub mod backoff;
pub mod client;
pub mod cluster;
pub mod connection;
pub mod enroll;
pub mod identity;
pub mod runner;

/// Version reported at enrollment and in `hello`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
