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
