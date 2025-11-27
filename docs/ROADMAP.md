# VPR Development Roadmap

**Last Updated**: 2025-11-27
**Current Status**: Production Ready (87/100)

---

## Priority Legend

- **P0** - Critical path, blocking production
- **P1** - Important for stealth/security
- **P2** - Operations and infrastructure
- **P3** - Nice-to-have features

---

## Completed

### Core VPN (P0)
- [x] MASQUE CONNECT-UDP (RFC 9298)
- [x] QUIC/HTTP3 transport (h3-quinn)
- [x] Hybrid Noise + ML-KEM768 handshake
- [x] TUN device management
- [x] NAT/routing on server
- [x] Client IP pool allocation
- [x] DNS configuration

### Security (P1)
- [x] Post-quantum cryptography
- [x] Key rotation (60s / 1GB)
- [x] Replay protection (5-min window)
- [x] Probe protection (challenge/response)
- [x] Zeroizing secrets
- [x] Kill switch with WAL pattern
- [x] NetworkStateGuard crash recovery
- [x] All VPR-SEC-001..009 fixes

### Stealth (P1)
- [x] TLS fingerprint customization (JA3/JA4)
- [x] AI Traffic Morpher (20M params)
- [x] Cover traffic generator
- [x] Adaptive padding
- [x] Chrome profile mimicry

### Client (P0)
- [x] Desktop GUI (Tauri)
- [x] TUI with ASCII Earth
- [x] Auto-connect
- [x] Connection statistics
- [x] Kill switch UI

### Infrastructure (P2)
- [x] CI/CD (GitHub Actions)
- [x] Terraform modules
- [x] Systemd services
- [x] 1,081 unit tests

---

## In Progress

### Code Quality (P1)
- [ ] Refactor large files (20 files >300 lines)
  - [ ] tun.rs (1,628 lines)
  - [ ] vpn_client.rs (1,567 lines)
  - [ ] vpn_server.rs (1,517 lines)
- [ ] Audit unwrap() calls (460 total)
- [ ] Fix HACK markers (8 total)

### Documentation (P2)
- [ ] Add doc comments to public API
- [ ] Per-crate README files
- [ ] API documentation site

---

## Planned

### Testing (P1)
- [ ] Integration tests for full VPN flow
- [ ] Fuzz testing for protocol parsing
- [ ] Performance benchmarks (criterion)
- [ ] Code coverage CI

### Mobile Clients (P2)
See [UX_IMPROVEMENT_ROADMAP.md](UX_IMPROVEMENT_ROADMAP.md)

- [ ] Android client (Kotlin + Rust FFI)
- [ ] iOS client (Swift + Rust FFI)
- [ ] Shared Rust core library

### Distribution (P2)
- [ ] Linux: AppImage, deb, rpm, AUR
- [ ] macOS: DMG with drag-and-drop
- [ ] Windows: MSI installer
- [ ] Config file support (~/.config/vpr/config.toml)

### Advanced Features (P3)
- [ ] Multi-hop VPN (double encryption)
- [ ] Split tunneling per-app
- [ ] WebRTC fallback transport
- [ ] DPDK for high-performance ingress

### Enterprise (P3)
- [ ] Admin dashboard
- [ ] SSO integration
- [ ] Audit logging
- [ ] Custom server deployment

---

## Timeline Estimate

| Phase | Duration | Focus |
|-------|----------|-------|
| Q4 2025 | Now | Code quality, documentation |
| Q1 2026 | 8 weeks | Mobile clients, installers |
| Q2 2026 | 4 weeks | Advanced features |
| Q3 2026 | Ongoing | Enterprise, maintenance |

---

## Metrics Goals

| Metric | Current | Target |
|--------|---------|--------|
| Overall Score | 87/100 | 95/100 |
| Code Quality | 85/100 | 92/100 |
| Documentation | 70/100 | 90/100 |
| Architecture | 82/100 | 90/100 |

---

## Related Documents

- [TODO.md](../TODO.md) - Immediate tasks
- [UX_IMPROVEMENT_ROADMAP.md](UX_IMPROVEMENT_ROADMAP.md) - User experience plan
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Developer guide
- [architecture.md](architecture.md) - System design
