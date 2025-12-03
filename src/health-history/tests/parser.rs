use assert_cmd::Command;
use health_history::{classify_suspicion, parse_report, Severity};

#[test]
fn classify_thresholds() {
    assert_eq!(classify_suspicion(0.2), Severity::Ok);
    assert_eq!(classify_suspicion(0.5), Severity::Warn);
    assert_eq!(classify_suspicion(0.9), Severity::Critical);
}

#[test]
fn parse_report_basic() {
    let raw = r#"{
        "target": "alpha",
        "suspicion": 0.5,
        "generated_at": 123,
        "results": [
            {"transport": "doh", "ok": true, "latency_ms": 900, "jitter_ms": 120}
        ]
    }"#;

    let report = parse_report(raw).expect("parse");
    assert_eq!(report.target, "alpha");
    assert_eq!(report.severity, Severity::Warn);
    assert_eq!(report.results.len(), 1);
    assert!(report.results[0].ok);
}

#[test]
fn cli_json_output() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "{\"target\":\"beta\",\"suspicion\":0.3,\"generated_at\":456}\n",
    )
    .unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("health-history"));
    cmd.arg("--path")
        .arg(tmp.path())
        .arg("--tail")
        .arg("1")
        .arg("--json");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("beta"));
}
