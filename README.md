# VPR - Post-Quantum Stealth VPN

**VPR** (VPN Protocol Router) is an ultra-performant, stealth VPN protocol designed for hostile network environments. Built to bypass advanced DPI, censorship, and state-level surveillance.

## Key Features

- **Post-Quantum Cryptography**: Hybrid Noise_IK + ML-KEM768 + X25519
- **DPI Evasion**: TLS fingerprint mimicry (JA3/JA4), adaptive traffic morphing
- **MASQUE/QUIC Transport**: High-performance HTTP/3-based tunneling
- **Stealth Mode**: Probe protection, replay protection, domain fronting
- **AI Traffic Morpher**: 20M parameter neural network for traffic obfuscation
- **Kill Switch**: WAL-based crash recovery with NetworkStateGuard

## Project Status

| Metric | Value | Status |
|--------|-------|--------|
| **Overall Score** | 87/100 | Production Ready |
| Tests | 1,081 passing | All green |
| Clippy Errors | 0 | Clean |
| Security Fixes | VPR-SEC-001..009 | All resolved |
| E2E Tested | Real VPS | Working |

**Last Audit**: 2025-11-27 ([Full Report](AUDIT_REPORT_2025-11-27.md))

## Quick Start

### Requirements

- Rust 1.70+ (edition 2021)
- Linux (macOS/Windows in development)
- Root privileges for TUN device

### Build

```bash
git clone https://github.com/AmirTlinov/VPR.git
cd VPR
cargo build --release
cargo test --all
```

### Client

```bash
# Generate Noise keys
./scripts/gen-noise-keys.sh secrets client

# Connect to server
sudo ./target/release/vpn-client \
  --server your-server.com:443 \
  --tun-name vpr0 \
  --noise-dir secrets \
  --noise-name client \
  --server-pub secrets/server.noise.pub
```

### Server

```bash
# Generate server keys
./scripts/gen-noise-keys.sh secrets server

# Generate TLS certificates (or use Let's Encrypt)
openssl req -x509 -newkey rsa:4096 -keyout secrets/server.key \
  -out secrets/server.crt -days 365 -nodes -subj "/CN=vpn.example.com"

# Start server
sudo ./target/release/vpn-server \
  --bind 0.0.0.0:443 \
  --tun-name vpr-srv \
  --tun-addr 10.9.0.1 \
  --pool-start 10.9.0.2 \
  --pool-end 10.9.0.254 \
  --noise-dir secrets \
  --noise-name server \
  --cert secrets/server.crt \
  --key secrets/server.key \
  --enable-forwarding
```

## Architecture

```
Client                           Server
┌─────────────────┐              ┌─────────────────┐
│   Application   │              │   Application   │
├─────────────────┤              ├─────────────────┤
│   TUN Device    │              │   TUN Device    │
│     (vpr0)      │              │    (vpr-srv)    │
├─────────────────┤              ├─────────────────┤
│  Traffic Morpher│              │   NAT/Routing   │
│    (AI 20M)     │              │                 │
├─────────────────┤   QUIC/443   ├─────────────────┤
│  MASQUE/HTTP3   │◄────────────►│  MASQUE/HTTP3   │
├─────────────────┤              ├─────────────────┤
│  Noise + ML-KEM │              │  Noise + ML-KEM │
│   (PQ Crypto)   │              │   (PQ Crypto)   │
├─────────────────┤              ├─────────────────┤
│  TLS Fingerprint│              │   DoH Gateway   │
│    (Chrome)     │              │  (DoH/DoQ/ODoH) │
└─────────────────┘              └─────────────────┘
```

## Project Structure

```
src/
├── masque-core/      # MASQUE CONNECT-UDP, QUIC transport
├── vpr-crypto/       # Noise protocol, ML-KEM, key management
├── vpr-ai/           # AI traffic morpher (ONNX)
├── vpr-app/          # Desktop GUI (Tauri)
├── vpr-tui/          # Terminal UI with ASCII Earth
├── vpr-e2e/          # E2E testing framework
├── health-harness/   # Health monitoring
├── health-history/   # Health data CLI
└── diagnostics/      # System diagnostics
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design and components |
| [Security](docs/security.md) | Threat model, crypto details |
| [User Guide](docs/user-guide.md) | End-user documentation |
| [CONTRIBUTING](CONTRIBUTING.md) | Developer guide |
| [ROADMAP](docs/ROADMAP.md) | Development plan |
| [UX Roadmap](docs/UX_IMPROVEMENT_ROADMAP.md) | UX improvement plan |

## Security

VPR implements defense-in-depth security:

| Feature | Implementation |
|---------|----------------|
| **Post-Quantum** | ML-KEM768 + X25519 hybrid |
| **Key Rotation** | 60s or 1GB threshold |
| **Secret Hygiene** | Zeroizing, no hardcoded secrets |
| **Replay Protection** | 5-minute sliding window |
| **Probe Protection** | Challenge/response system |
| **Constant-Time** | subtle crate for crypto ops |

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Testing

```bash
# All tests
cargo test --all

# Specific crate
cargo test -p masque-core
cargo test -p vpr-crypto

# Clippy
cargo clippy --all-targets --all-features

# Format check
cargo fmt --check
```

## Contributing

We welcome contributions! Please read:

1. [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
2. [Code of Conduct](CODE_OF_CONDUCT.md) - Community standards

### Quality Standards

- Cyclomatic complexity <= 10
- Test coverage >= 85% on changed code
- No mocks/fakes in production code
- Conventional Commits format

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Built with:
- [QUIC](https://quicwg.org/) / [MASQUE](https://datatracker.ietf.org/wg/masque/about/)
- [Noise Protocol](https://noiseprotocol.org/)
- [ML-KEM (CRYSTALS-Kyber)](https://pq-crystals.org/kyber/)
- [Tauri](https://tauri.app/)
- [Rust](https://www.rust-lang.org/)

---

**VPR** - Freedom through technology
