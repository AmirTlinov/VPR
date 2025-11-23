# VPR Roadmap — Missing Features for Production VPN

> Auto-generated roadmap based on codebase analysis. Last updated: 2025-11-24

## Priority Legend
- **P0** — Blocker for functional VPN tunnel
- **P1** — Required for stealth/DPI-resistance
- **P2** — Ops/DX improvements

---

## P0 — Critical Path to Working VPN

| # | Feature | Description | Owner | ETA | Effort |
|---|---------|-------------|-------|-----|--------|
| 1 | **MASQUE CONNECT-UDP (RFC 9298)** | Replace current TCP/UDP proxy with proper MASQUE datagrams over HTTP/3. Required for UDP app tunneling (DNS, QUIC, games). | TBD | TBD | ~2w |
| 2 | **TUN/TAP integration** | Virtual network interface for full traffic capture. Platform-specific (tun2 crate on Linux, utun on macOS). | TBD | TBD | ~1w |
| 3 | **VPN Client binary** | Counterpart to masque-core server: connect, authenticate, establish tunnel, configure routes. | TBD | TBD | ~2w |
| 4 | **Routing & NAT** | IP routing rules + masquerading on server side. Client-side split-tunnel support. | TBD | TBD | ~1w |

## P1 — Stealth & Security Hardening

| # | Feature | Description | Owner | ETA | Effort |
|---|---------|-------------|-------|-----|--------|
| 5 | **Adaptive traffic shaping** | Cover traffic patterns mimicking HTTP/3, WebRTC. Trace-driven padding buckets to defeat DPI fingerprinting. | TBD | TBD | ~2w |
| 6 | **Session ticket rotation** | Rotate session keys every ≤60s or 1GB. Instrumentation hooks for telemetry. | TBD | TBD | ~3d |
| 7 | **Bootstrap manifest system** | Signed JSON manifest with endpoints, certs, health. Stego RSS publisher for censorship-resistant distribution. | TBD | TBD | ~1w |
| 8 | **Moving-target DoH rotation** | Automated ACME cert issuance + DNS update + manifest push for DoH endpoint rotation. | TBD | TBD | ~1w |

## P2 — DNS Plane & Infrastructure

| # | Feature | Description | Owner | ETA | Effort |
|---|---------|-------------|-------|-----|--------|
| 9 | **Hidden-master DNS** | Home-node authoritative server with DNSSEC (ZSK weekly, KSK monthly). | TBD | TBD | ~1w |
| 10 | **IXFR sync pipeline** | Signed incremental zone transfer over WireGuard to VPS resolver. | TBD | TBD | ~3d |
| 11 | **Offline root CA tooling** | Air-gapped CA generation + intermediate cert issuance scripts. | TBD | TBD | ~3d |
| 12 | **Key rotation policy** | Documented procedures + automation for cert/key rotation. | TBD | TBD | ~2d |

## P3 — Ops & Developer Experience

| # | Feature | Description | Owner | ETA | Effort |
|---|---------|-------------|-------|-----|--------|
| 13 | **CI/CD pipeline** | GitHub Actions: lint, fmt, test, coverage, release builds. | TBD | TBD | ~2d |
| 14 | **GUI packaging** | PyInstaller/Briefcase for Linux/macOS distribution. | TBD | TBD | ~2d |
| 15 | **Network-namespace test harness** | Non-disruptive tunnel tests in isolated namespaces. | TBD | TBD | ~3d |
| 16 | **Chaos testing suite** | Packet loss, QUIC blocking, DNS poisoning scenarios. | TBD | TBD | ~1w |
| 17 | **Architecture documentation** | Expand 1.logic into full docs/architecture.md. | TBD | TBD | ~2d |

---

## Current State Summary

### ✅ Implemented
- `vpr-crypto`: PKI, hybrid Noise+ML-KEM768, age encryption
- `masque-core`: TLS+Noise TCP/UDP proxy (not yet MASQUE)
- `doh-gateway`: DoH/DoQ endpoints
- `health-harness`: Health monitoring
- `vpr-app`: PySide6 GUI (partial)
- Bootstrap scripts + systemd units

### 🔄 In Progress
- TASK-001: Deploy minimal VPR stack on VPS (33%)

### ❌ Blocking Full VPN
1. No MASQUE CONNECT-UDP — only TCP/UDP proxy exists
2. No TUN/TAP — can't capture system traffic
3. No client — server-only implementation
4. No routing — traffic goes nowhere

---

## Recommended Next Steps

1. **Implement MASQUE CONNECT-UDP** over existing quinn/HTTP/3 stack
2. **Add TUN device** using `tun2` crate with async tokio integration
3. **Build client binary** sharing crypto/protocol code with server
4. **Add basic routing** with iptables/nftables automation

Total estimated effort to MVP: **~6-8 weeks** of focused development.
