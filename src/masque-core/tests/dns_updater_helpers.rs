//! Tests for dns_updater module (public API only)
//!
//! Note: extract_root_domain is private implementation detail.
//! Test only the public interface: DnsUpdaterConfig, DnsUpdaterFactory.

use masque_core::dns_updater::{DnsProvider, DnsUpdaterConfig, DnsUpdaterFactory};
use std::time::Duration;

#[test]
fn dns_updater_config_defaults() {
    let config = DnsUpdaterConfig::default();
    assert!(matches!(config.provider, DnsProvider::Manual));
    assert!(config.credentials.is_empty());
    assert!(config.timeout > Duration::ZERO);
}

#[test]
fn dns_updater_factory_rejects_manual_provider() {
    // Manual provider intentionally fails - it doesn't support automatic updates
    let config = DnsUpdaterConfig::default();
    let updater = DnsUpdaterFactory::create(&config);
    assert!(
        updater.is_err(),
        "Manual provider should fail (does not support automatic updates)"
    );
}

#[test]
fn dns_updater_factory_requires_cloudflare_credentials() {
    let config = DnsUpdaterConfig {
        provider: DnsProvider::Cloudflare,
        credentials: std::collections::HashMap::new(), // Missing api_token
        timeout: Duration::from_secs(30),
        propagation_delay: Duration::from_secs(10),
    };
    let result = DnsUpdaterFactory::create(&config);
    assert!(
        result.is_err(),
        "Cloudflare without credentials should fail"
    );
}
