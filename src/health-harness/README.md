# Health Harness

VPN health check tool for testing multiple transport protocols.

## Features

- **Multi-Transport Testing** - DoH, DoQ, ODoH support
- **Latency Measurement** - Per-transport latency samples
- **Jitter Analysis** - Connection stability metrics
- **JSON Output** - Machine-readable results

## Supported Transports

| Transport | Description |
|-----------|-------------|
| DoH | DNS over HTTPS |
| DoQ | DNS over QUIC |
| ODoH | Oblivious DNS over HTTPS |

## Quick Start

```bash
# Test DoH endpoint
cargo run --bin health-harness -- --doh-url https://dns.google/dns-query

# Test DoQ endpoint
cargo run --bin health-harness -- --doq-addr 8.8.8.8:853

# Test ODoH endpoint
cargo run --bin health-harness -- \
  --odoh-url https://odoh.example.com \
  --odoh-config-url https://odoh.example.com/.well-known/odohconfigs
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--doh-url` | DoH endpoint URL |
| `--doq-addr` | DoQ endpoint address:port |
| `--odoh-url` | ODoH endpoint URL |
| `--odoh-config-url` | ODoH config URL |
| `--name` | Domain to resolve (default: example.com) |
| `--timeout-secs` | Timeout in seconds (default: 5) |
| `--samples` | Number of samples (default: 1) |
| `--server-name` | Override TLS server name |
| `--insecure-tls` | Skip TLS verification |

## Output Format

```json
{
  "transport": "doh",
  "ok": true,
  "latency_ms": 42,
  "jitter_ms": 3.5,
  "samples": 10
}
```

## Integration

Results can be piped to `health-history` for storage:

```bash
cargo run --bin health-harness -- --doh-url https://dns.google/dns-query | \
  tee -a ~/.vpr/health_reports.jsonl
```

## Testing

```bash
cargo test -p health-harness
```
