# VPR E2E Test Runner

Automated end-to-end testing framework for VPR VPN.

## Features

- **One-command deployment** - Deploy server, sync keys, run tests
- **Automatic key sync** - Downloads server public key, generates client keys
- **Test battery** - Ping, DNS, external connectivity, latency, throughput
- **Multiple output formats** - JSON and Markdown reports
- **CI/CD ready** - Exit codes, structured output

## Quick Start

### Option 1: Environment Variables (Recommended)

```bash
# Set credentials
export VPR_E2E_HOST="64.176.70.203"
export VPR_E2E_PASSWORD="your_password"

# Run full E2E test
sudo cargo run --bin vpr-e2e -- --deploy --insecure
```

### Option 2: CLI Arguments

```bash
sudo cargo run --bin vpr-e2e -- \
  --host 64.176.70.203 \
  --password 'your_password' \
  --deploy \
  --insecure
```

### Option 3: Config File

```bash
# Create config
cp config/e2e.sample.json config/e2e.json
# Edit config/e2e.json with your settings

# Run
sudo cargo run --bin vpr-e2e -- --config config/e2e.json --deploy
```

## Commands

| Command | Description |
|---------|-------------|
| (default) | Full E2E: deploy (if --deploy), connect, test, report |
| `deploy` | Deploy/update server only |
| `test` | Run tests only (server must be running) |
| `status` | Show server status and logs |
| `stop` | Stop remote server |

## CLI Options

| Flag | Description |
|------|-------------|
| `--host` | Server IP address |
| `--password` | SSH password (or VPR_E2E_PASSWORD) |
| `--user` | SSH user (default: root) |
| `--port` | VPN port (default: 4433) |
| `--deploy` | Deploy/update server before testing |
| `--rebuild` | Force rebuild of binaries |
| `--insecure` | Skip TLS verification (testing only!) |
| `--config` | Config file path |
| `--output` | Output directory (default: logs/e2e) |
| `--verbose` | Verbose output |
| `--keep-alive` | Keep VPN running after tests |

## Output

Reports are saved to `logs/e2e/`:
- `report_YYYYMMDD_HHMMSS.json` - Machine-readable
- `report_YYYYMMDD_HHMMSS.md` - Human-readable

## Tests

| Test | Description |
|------|-------------|
| `ping_gateway` | Ping VPN gateway (10.8.0.1) |
| `dns_resolution` | DNS lookup via 8.8.8.8 |
| `external_connectivity` | Get public IP via ifconfig.me |
| `latency` | Latency to multiple endpoints |
| `throughput` | Download speed test (optional) |

## CI/CD Integration

```yaml
# GitHub Actions example
- name: E2E Test
  run: |
    sudo cargo run --release --bin vpr-e2e -- \
      --host ${{ secrets.VPR_HOST }} \
      --password ${{ secrets.VPR_PASSWORD }} \
      --deploy --insecure
  env:
    VPR_E2E_HOST: ${{ secrets.VPR_HOST }}
    VPR_E2E_PASSWORD: ${{ secrets.VPR_PASSWORD }}
```

## Requirements

- Linux with sudo access
- `sshpass` installed (`apt install sshpass`)
- `dig` for DNS tests (`apt install dnsutils`)
- `curl` for connectivity tests
