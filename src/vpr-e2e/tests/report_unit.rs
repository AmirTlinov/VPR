//! Unit tests for E2E report types
use vpr_e2e::report::{E2eReport, TestResult};

#[test]
fn test_result_serializes() {
    let result = TestResult {
        name: "ping".into(),
        passed: true,
        duration_ms: 120,
        details: Some("ok".into()),
        metrics: None,
        error: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("ping"));
    assert!(json.contains("passed"));
}

#[test]
fn e2e_report_serializes() {
    let mut report = E2eReport::new("127.0.0.1".into(), 4433, "chrome".into());
    report.add_test(TestResult {
        name: "connection".into(),
        passed: true,
        duration_ms: 50,
        details: Some("connected".into()),
        metrics: None,
        error: None,
    });

    let json = serde_json::to_string(&report).unwrap();
    let back: E2eReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tests.len(), 1);
    assert!(back.tests[0].passed);
    assert_eq!(back.tests_passed, 1);
    assert_eq!(back.tests_failed, 0);
}

#[test]
fn e2e_report_tracks_pass_fail() {
    let mut report = E2eReport::new("localhost".into(), 443, "firefox".into());

    report.add_test(TestResult {
        name: "test1".into(),
        passed: true,
        duration_ms: 10,
        details: None,
        metrics: None,
        error: None,
    });
    report.add_test(TestResult {
        name: "test2".into(),
        passed: false,
        duration_ms: 20,
        details: None,
        metrics: None,
        error: Some("failed".into()),
    });

    assert_eq!(report.tests_passed, 1);
    assert_eq!(report.tests_failed, 1);
    assert_eq!(report.total_duration_ms, 30);
    assert!(!report.all_passed());
}
