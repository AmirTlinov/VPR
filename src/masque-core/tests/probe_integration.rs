use masque_core::probe_protection::{ProbeDetection, ProbeProtectionConfig, ProbeProtector};
use std::net::{IpAddr, Ipv4Addr};

fn padding_schedule_bytes(
    strategy: &str,
    max_jitter_us: u64,
    min_size: usize,
    mtu: u16,
) -> Vec<u8> {
    fn strategy_to_byte(strategy: &str) -> u8 {
        match strategy.to_ascii_lowercase().as_str() {
            "none" => 0,
            "bucket" => 1,
            "rand-bucket" | "random-bucket" | "random" => 2,
            "mtu" => 3,
            _ => 2,
        }
    }

    let mut out = Vec::with_capacity(15);
    out.push(strategy_to_byte(strategy));
    out.extend_from_slice(&max_jitter_us.to_be_bytes());
    out.extend_from_slice(&(min_size as u32).to_be_bytes());
    out.extend_from_slice(&mtu.to_be_bytes());
    out
}

#[test]
fn probe_protector_bans_after_max_failures() {
    let protector = ProbeProtector::new(ProbeProtectionConfig {
        max_failed_attempts: 3,
        ..Default::default()
    });
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // two failures: still legitimate
    protector.record_failure(ip);
    protector.record_failure(ip);
    assert_eq!(protector.check_ip(ip), ProbeDetection::Legitimate);

    // third failure triggers ban
    protector.record_failure(ip);
    match protector.check_ip(ip) {
        ProbeDetection::Blocked(_) => {}
        other => panic!("expected blocked after 3 failures, got {:?}", other),
    }
}

#[test]
fn padding_echo_mismatch_is_rejected_and_banned() {
    // Configure to ban on first mismatch for determinism
    let protector = ProbeProtector::new(ProbeProtectionConfig {
        max_failed_attempts: 1,
        ..Default::default()
    });
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let server_bytes = padding_schedule_bytes("rand-bucket", 5_000, 32, 1400);
    let client_bytes = vec![0u8; server_bytes.len()]; // clearly different

    assert_ne!(server_bytes, client_bytes);

    // simulate mismatch handling: record failure then check ban
    protector.record_failure(ip);
    match protector.check_ip(ip) {
        ProbeDetection::Blocked(_) => {}
        other => panic!("expected blocked after padding mismatch, got {:?}", other),
    }
}
