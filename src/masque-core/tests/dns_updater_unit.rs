use masque_core::dns_updater::{DnsProvider, DnsUpdaterConfig};

#[test]
fn provider_parse_variants() {
    assert_eq!(
        DnsProvider::parse("cloudflare"),
        Some(DnsProvider::Cloudflare)
    );
    assert_eq!(DnsProvider::parse("CF"), Some(DnsProvider::Cloudflare));
    assert_eq!(DnsProvider::parse("route53"), Some(DnsProvider::Route53));
    assert_eq!(DnsProvider::parse("aws"), Some(DnsProvider::Route53));
    assert_eq!(DnsProvider::parse("http"), Some(DnsProvider::HttpApi));
    assert_eq!(DnsProvider::parse("manual"), None);
}

#[test]
fn config_default_sane_values() {
    let cfg = DnsUpdaterConfig::default();
    assert_eq!(cfg.timeout.as_secs(), 30);
    assert_eq!(cfg.propagation_delay.as_secs(), 10);
    // Manual by default, no credentials
    assert!(cfg.credentials.is_empty());
}
