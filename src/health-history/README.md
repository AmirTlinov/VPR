# Health History

VPN health report storage and analysis.

## Features

- **JSONL Storage** - Append-only health reports
- **Suspicion Scoring** - DPI detection risk analysis
- **Report Parsing** - Structured health report parsing
- **History Management** - Tail, filter, analyze

## Suspicion Scoring

| Score | Severity | Meaning |
|-------|----------|---------|
| < 0.35 | OK | Traffic looks normal |
| 0.35-0.75 | Warn | Elevated detection risk |
| >= 0.75 | Critical | Likely flagged by DPI |

## File Format

Reports are stored as JSON Lines (`~/.vpr/health_reports.jsonl`):

```json
{"suspicion":0.2,"target":"server1","results":[{"transport":"masque","ok":true,"latency_ms":15.3}]}
{"suspicion":0.45,"target":"server1","results":[{"transport":"masque","ok":true,"latency_ms":22.1}]}
```

## Quick Start

```rust
use health_history::{load_reports, parse_report, default_path, classify_suspicion};

// Load reports
let path = default_path(); // ~/.vpr/health_reports.jsonl
let reports = load_reports(&path)?;

// Parse and analyze
for raw in reports {
    let report = parse_report(&raw.to_string())?;
    println!("{}: {:?}", report.target, report.severity);
}

// Classify suspicion manually
let severity = classify_suspicion(0.5); // Severity::Warn
```

## Data Structures

### HealthReport

```rust
pub struct HealthReport {
    pub target: String,
    pub suspicion: f64,
    pub severity: Severity,
    pub generated_at: Option<f64>,
    pub results: Vec<TransportResult>,
}
```

### TransportResult

```rust
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
```

## Testing

```bash
cargo test -p health-history
```

## Binary

The `health-history` binary provides CLI access:

```bash
# View recent reports
cargo run --bin health-history -- --tail 10

# JSON output
cargo run --bin health-history -- --json
```
