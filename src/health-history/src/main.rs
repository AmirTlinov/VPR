use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use health_history::{classify_suspicion, default_path, load_reports, tail_reports};

#[derive(Parser, Debug)]
#[command(
    name = "health-history",
    about = "Inspect VPR health reports (Rust replacement for python script)"
)]
struct Args {
    #[arg(long, default_value_t = 10)]
    tail: usize,
    #[arg(long, default_value_os_t = default_path())]
    path: PathBuf,
    #[arg(long, default_value_t = false)]
    json: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let reports = load_reports(&args.path)?;
    if reports.is_empty() {
        println!("[INFO] No reports found at {}", args.path.display());
        return Ok(());
    }

    let reports = tail_reports(reports, args.tail);

    if args.json {
        let rendered = serde_json::to_string_pretty(&reports)?;
        println!("{}", rendered);
        return Ok(());
    }

    let mut suspicions = Vec::new();
    for r in &reports {
        if let Some(s) = r.get("suspicion").and_then(|v| v.as_f64()) {
            suspicions.push(s);
        }
    }
    let avg_susp = if suspicions.is_empty() {
        0.0
    } else {
        suspicions.iter().sum::<f64>() / suspicions.len() as f64
    };

    println!(
        "Showing {} report(s) from {}",
        reports.len(),
        args.path.display()
    );
    println!("Average suspicion: {:.2}", avg_susp);

    for report in reports.iter().rev() {
        let target = report
            .get("target")
            .or_else(|| report.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or("node");
        let suspicion_val = report
            .get("suspicion")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let severity = classify_suspicion(suspicion_val).as_str();
        let transports = report
            .get("results")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(format_transport)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        println!(
            "- target={} suspicion={:.2} [{}]",
            target, suspicion_val, severity
        );
        if !transports.is_empty() {
            println!("  transports: {}", transports);
        }
    }

    Ok(())
}

fn format_transport(entry: &serde_json::Value) -> String {
    let name = entry
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_uppercase();
    let status = if entry.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        "OK"
    } else {
        "FAIL"
    };
    let latency = entry
        .get("latency_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let jitter = entry
        .get("jitter_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let detail = entry
        .get("detail")
        .and_then(|v| v.as_str())
        .map(|s| format!(" detail={}", s))
        .unwrap_or_default();
    format!(
        "{}:{}(lat={:.0}ms jitter={:.1}{} )",
        name, status, latency, jitter, detail
    )
}
