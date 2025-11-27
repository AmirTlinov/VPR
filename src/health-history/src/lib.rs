//! Health History - VPN Health Report Storage and Analysis
//!
//! This crate handles storage and analysis of VPN health reports in JSONL format.
//! Each line in the history file represents a single health check with suspicion
//! scores and transport-level metrics.
//!
//! # Suspicion Scoring
//!
//! The suspicion score (0.0-1.0) indicates DPI detection risk:
//!
//! | Score | Severity | Meaning |
//! |-------|----------|---------|
//! | < 0.35 | OK | Traffic looks normal |
//! | 0.35-0.75 | Warn | Elevated detection risk |
//! | ≥ 0.75 | Critical | Likely flagged by DPI |
//!
//! # File Format
//!
//! Reports are stored as JSON Lines (`.jsonl`):
//!
//! ```json
//! {"suspicion":0.2,"target":"server1","results":[{"transport":"masque","ok":true,"latency_ms":15.3}]}
//! {"suspicion":0.45,"target":"server1","results":[{"transport":"masque","ok":true,"latency_ms":22.1}]}
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use health_history::{load_reports, parse_report, default_path};
//!
//! let path = default_path(); // ~/.vpr/health_reports.jsonl
//! let reports = load_reports(&path)?;
//! for raw in reports {
//!     let report = parse_report(&raw.to_string())?;
//!     println!("{}: {:?}", report.target, report.severity);
//! }
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufRead, io::BufReader, path::PathBuf};

pub const DEFAULT_FILENAME: &str = "health_reports.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Ok,
    Warn,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransportResult {
    pub transport: String,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub samples: Option<u32>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthReport {
    pub target: String,
    pub suspicion: f64,
    pub severity: Severity,
    pub generated_at: Option<f64>,
    pub results: Vec<TransportResult>,
}

pub fn classify_suspicion(value: f64) -> Severity {
    if value < 0.35 {
        Severity::Ok
    } else if value < 0.75 {
        Severity::Warn
    } else {
        Severity::Critical
    }
}

pub fn parse_report(raw: &str) -> Result<HealthReport> {
    let mut value: serde_json::Value = serde_json::from_str(raw).context("parse json")?;

    let suspicion = value
        .get("suspicion")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let severity = classify_suspicion(suspicion);

    let target = value
        .get("target")
        .or_else(|| value.get("query"))
        .and_then(|v| v.as_str())
        .unwrap_or("node")
        .to_string();

    let generated_at = value.get("generated_at").and_then(|v| v.as_f64());

    let mut results = Vec::new();
    if let Some(arr) = value.get_mut("results").and_then(|v| v.as_array_mut()) {
        for entry in arr.drain(..) {
            results.push(TransportResult {
                transport: entry
                    .get("transport")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                ok: entry.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
                latency_ms: entry.get("latency_ms").and_then(|v| v.as_f64()),
                jitter_ms: entry.get("jitter_ms").and_then(|v| v.as_f64()),
                samples: entry
                    .get("samples")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32),
                bytes_in: entry.get("bytes_in").and_then(|v| v.as_u64()),
                bytes_out: entry.get("bytes_out").and_then(|v| v.as_u64()),
                detail: entry
                    .get("detail")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }

    Ok(HealthReport {
        target,
        suspicion,
        severity,
        generated_at,
        results,
    })
}

pub fn default_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("~"))
        .join(".vpr")
        .join(DEFAULT_FILENAME)
}

pub fn load_reports(path: &PathBuf) -> Result<Vec<serde_json::Value>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(&line) {
            Ok(v) => out.push(v),
            Err(err) => {
                eprintln!("[WARN] Skipping malformed line {}: {}", idx + 1, err);
            }
        }
    }
    Ok(out)
}

pub fn tail_reports(mut reports: Vec<serde_json::Value>, tail: usize) -> Vec<serde_json::Value> {
    if tail == 0 || reports.is_empty() {
        return reports;
    }
    let len = reports.len();
    if tail >= len {
        return reports;
    }
    reports.split_off(len - tail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn classify_suspicion_buckets() {
        assert_eq!(classify_suspicion(0.1), Severity::Ok);
        assert_eq!(classify_suspicion(0.5), Severity::Warn);
        assert_eq!(classify_suspicion(0.9), Severity::Critical);
    }

    #[test]
    fn classify_suspicion_boundaries() {
        // Boundary at 0.35
        assert_eq!(classify_suspicion(0.34), Severity::Ok);
        assert_eq!(classify_suspicion(0.35), Severity::Warn);
        // Boundary at 0.75
        assert_eq!(classify_suspicion(0.74), Severity::Warn);
        assert_eq!(classify_suspicion(0.75), Severity::Critical);
    }

    #[test]
    fn severity_as_str() {
        assert_eq!(Severity::Ok.as_str(), "OK");
        assert_eq!(Severity::Warn.as_str(), "WARN");
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn tail_reports_limits() {
        let data = vec![serde_json::json!({"a":1}), serde_json::json!({"a":2})];
        let out = tail_reports(data.clone(), 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["a"], 2);

        let out_full = tail_reports(data.clone(), 5);
        assert_eq!(out_full.len(), 2);
    }

    #[test]
    fn tail_reports_zero() {
        let data = vec![serde_json::json!({"a":1})];
        let out = tail_reports(data.clone(), 0);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn tail_reports_empty() {
        let data: Vec<serde_json::Value> = vec![];
        let out = tail_reports(data, 5);
        assert!(out.is_empty());
    }

    #[test]
    fn tail_reports_exact() {
        let data = vec![serde_json::json!({"a":1}), serde_json::json!({"a":2})];
        let out = tail_reports(data.clone(), 2);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn parse_report_fills_defaults() {
        let raw = r#"{"suspicion":0.2,"results":[{"transport":"masque","ok":true}]}"#;
        let report = parse_report(raw).unwrap();
        assert_eq!(report.severity, Severity::Ok);
        assert_eq!(report.target, "node");
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].transport, "masque");
        assert!(report.results[0].ok);
    }

    #[test]
    fn parse_report_with_target() {
        let raw = r#"{"suspicion":0.5,"target":"server1","results":[]}"#;
        let report = parse_report(raw).unwrap();
        assert_eq!(report.target, "server1");
        assert_eq!(report.severity, Severity::Warn);
    }

    #[test]
    fn parse_report_with_query_fallback() {
        let raw = r#"{"suspicion":0.8,"query":"custom_query","results":[]}"#;
        let report = parse_report(raw).unwrap();
        assert_eq!(report.target, "custom_query");
        assert_eq!(report.severity, Severity::Critical);
    }

    #[test]
    fn parse_report_with_generated_at() {
        let raw = r#"{"suspicion":0.1,"generated_at":1234567890.5,"results":[]}"#;
        let report = parse_report(raw).unwrap();
        assert_eq!(report.generated_at, Some(1234567890.5));
    }

    #[test]
    fn parse_report_all_transport_fields() {
        let raw = r#"{
            "suspicion": 0.2,
            "results": [{
                "transport": "quic",
                "ok": true,
                "latency_ms": 15.5,
                "jitter_ms": 2.3,
                "samples": 100,
                "bytes_in": 1024,
                "bytes_out": 2048,
                "detail": "success"
            }]
        }"#;
        let report = parse_report(raw).unwrap();
        let result = &report.results[0];
        assert_eq!(result.transport, "quic");
        assert!(result.ok);
        assert_eq!(result.latency_ms, Some(15.5));
        assert_eq!(result.jitter_ms, Some(2.3));
        assert_eq!(result.samples, Some(100));
        assert_eq!(result.bytes_in, Some(1024));
        assert_eq!(result.bytes_out, Some(2048));
        assert_eq!(result.detail, Some("success".to_string()));
    }

    #[test]
    fn parse_report_transport_missing_fields() {
        let raw = r#"{"suspicion":0.1,"results":[{"ok":false}]}"#;
        let report = parse_report(raw).unwrap();
        let result = &report.results[0];
        assert_eq!(result.transport, "?");
        assert!(!result.ok);
        assert!(result.latency_ms.is_none());
        assert!(result.jitter_ms.is_none());
        assert!(result.samples.is_none());
        assert!(result.bytes_in.is_none());
        assert!(result.bytes_out.is_none());
        assert!(result.detail.is_none());
    }

    #[test]
    fn parse_report_invalid_json() {
        let raw = "not valid json";
        let result = parse_report(raw);
        assert!(result.is_err());
    }

    #[test]
    fn parse_report_no_results() {
        let raw = r#"{"suspicion":0.0}"#;
        let report = parse_report(raw).unwrap();
        assert!(report.results.is_empty());
    }

    #[test]
    fn default_path_contains_vpr() {
        let path = default_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".vpr"));
        assert!(path_str.contains(DEFAULT_FILENAME));
    }

    #[test]
    fn load_reports_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/file.jsonl");
        let reports = load_reports(&path).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn load_reports_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");
        File::create(&path).unwrap();

        let reports = load_reports(&path).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn load_reports_valid_jsonl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reports.jsonl");
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{"a": 1}}"#).unwrap();
        writeln!(file, r#"{{"b": 2}}"#).unwrap();

        let reports = load_reports(&path).unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0]["a"], 1);
        assert_eq!(reports[1]["b"], 2);
    }

    #[test]
    fn load_reports_skips_empty_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reports.jsonl");
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{"a": 1}}"#).unwrap();
        writeln!(file).unwrap(); // empty line
        writeln!(file, "   ").unwrap(); // whitespace only
        writeln!(file, r#"{{"b": 2}}"#).unwrap();

        let reports = load_reports(&path).unwrap();
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn load_reports_skips_malformed_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reports.jsonl");
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{"valid": 1}}"#).unwrap();
        writeln!(file, "invalid json").unwrap();
        writeln!(file, r#"{{"also_valid": 2}}"#).unwrap();

        let reports = load_reports(&path).unwrap();
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn transport_result_clone() {
        let result = TransportResult {
            transport: "test".to_string(),
            ok: true,
            latency_ms: Some(10.0),
            jitter_ms: Some(1.0),
            samples: Some(5),
            bytes_in: Some(100),
            bytes_out: Some(200),
            detail: Some("ok".to_string()),
        };
        let cloned = result.clone();
        assert_eq!(cloned.transport, result.transport);
        assert_eq!(cloned.latency_ms, result.latency_ms);
    }

    #[test]
    fn health_report_clone() {
        let report = HealthReport {
            target: "test".to_string(),
            suspicion: 0.5,
            severity: Severity::Warn,
            generated_at: Some(123.0),
            results: vec![],
        };
        let cloned = report.clone();
        assert_eq!(cloned.target, report.target);
        assert_eq!(cloned.severity, report.severity);
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Ok, Severity::Ok);
        assert_ne!(Severity::Ok, Severity::Warn);
        assert_ne!(Severity::Warn, Severity::Critical);
    }

    #[test]
    fn health_report_equality() {
        let r1 = HealthReport {
            target: "a".to_string(),
            suspicion: 0.0,
            severity: Severity::Ok,
            generated_at: None,
            results: vec![],
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }
}
