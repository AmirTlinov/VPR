//! Basic tests for health-history library types
use health_history::{parse_report, Severity, TransportResult};

#[test]
fn parse_report_with_full_data() {
    let raw = r#"{
        "target": "vpn-node-1",
        "suspicion": 0.2,
        "generated_at": 1700000000.0,
        "results": [
            {"transport": "masque", "ok": true, "latency_ms": 50.0},
            {"transport": "quic", "ok": false, "detail": "timeout"}
        ]
    }"#;

    let report = parse_report(raw).expect("should parse valid report");
    assert_eq!(report.target, "vpn-node-1");
    assert_eq!(report.severity, Severity::Ok);
    assert_eq!(report.results.len(), 2);
    assert!(report.results[0].ok);
    assert!(!report.results[1].ok);
}

#[test]
fn health_report_severity_classification() {
    use health_history::classify_suspicion;

    assert_eq!(classify_suspicion(0.0), Severity::Ok);
    assert_eq!(classify_suspicion(0.34), Severity::Ok);
    assert_eq!(classify_suspicion(0.35), Severity::Warn);
    assert_eq!(classify_suspicion(0.74), Severity::Warn);
    assert_eq!(classify_suspicion(0.75), Severity::Critical);
    assert_eq!(classify_suspicion(1.0), Severity::Critical);
}

#[test]
fn transport_result_optional_fields() {
    let result = TransportResult {
        transport: "masque".into(),
        ok: true,
        latency_ms: Some(42.5),
        jitter_ms: None,
        samples: Some(10),
        bytes_in: Some(1024),
        bytes_out: Some(512),
        detail: None,
    };

    assert_eq!(result.transport, "masque");
    assert!(result.ok);
    assert_eq!(result.latency_ms, Some(42.5));
    assert!(result.jitter_ms.is_none());
}
