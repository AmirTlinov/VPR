//! VPN client library components.
//!
//! This module provides reusable components for the VPN client binary,
//! extracted for better modularity and testability.

mod args;
mod builders;
mod probe;
mod tls;

pub use args::Args;
pub use builders::{build_padder_cli, build_padder_from_config};
pub use probe::{handle_probe_challenge, solve_pow};
pub use tls::{build_quic_config, InsecureVerifier};

/// Protocol version for VPR client-server communication
pub const VPR_PROTOCOL_VERSION: u8 = 0x01;
