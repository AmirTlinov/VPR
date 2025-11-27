# VPR TODO

**Status**: Production Ready (87/100)
**Last Updated**: 2025-11-27

> For detailed roadmap see [docs/ROADMAP.md](docs/ROADMAP.md)

---

## Immediate (P0)

### Code Quality
- [ ] Audit 460 `unwrap()` calls for panic safety
- [ ] Refactor large files (>300 lines):
  - [ ] `tun.rs` (1,628 lines)
  - [ ] `vpn_client.rs` (1,567 lines)
  - [ ] `vpn_server.rs` (1,517 lines)

### Documentation
- [ ] Add doc comments to public API (~40% undocumented)
- [ ] Create per-crate README files

---

## Short-term (P1)

### Testing
- [ ] Add integration tests for full VPN flow
- [ ] Add benchmarks with criterion

### Security
- [ ] Fix 8 HACK markers with proper solutions
- [ ] Add fuzz testing for protocol parsing

---

## Long-term (P2)

### Features
- [ ] Mobile clients (iOS/Android) - see [UX Roadmap](docs/UX_IMPROVEMENT_ROADMAP.md)
- [ ] One-click installers (AppImage, DMG, MSI)
- [ ] Config file support

### Infrastructure
- [ ] Code coverage CI
- [ ] Release automation

---

## Completed

- [x] All VPR-SEC-001..009 security fixes
- [x] 1,081 tests passing
- [x] E2E tested with real VPS
- [x] Post-quantum cryptography
- [x] Kill switch with WAL pattern
- [x] TLS fingerprint mimicry

---

## Links

- [ROADMAP](docs/ROADMAP.md) - Full development roadmap
- [UX Roadmap](docs/UX_IMPROVEMENT_ROADMAP.md) - User experience plan
- [AUDIT REPORT](AUDIT_REPORT_2025-11-27.md) - Latest audit
- [CONTRIBUTING](CONTRIBUTING.md) - Developer guide
