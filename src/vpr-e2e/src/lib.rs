//! VPR E2E Testing Framework
//!
//! This crate provides automated end-to-end testing for VPR VPN:
//! - Server deployment via SSH
//! - Key synchronization
//! - Connection testing
//! - Report generation

pub mod config;
pub mod deployer;
pub mod report;
pub mod tests;

pub use config::E2eConfig;
pub use deployer::Deployer;
pub use report::{E2eReport, TestResult};
pub use tests::TestRunner;
