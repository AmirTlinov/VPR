# VPR TODO

**Status**: Production Ready (92/100)
**Last Updated**: 2025-11-27

> For detailed roadmap see [docs/ROADMAP.md](docs/ROADMAP.md)

---

## Immediate (P0)

### Code Quality
- [x] Audit `unwrap()` calls for panic safety (608 audited, 3 fixed)
- [x] Refactor large files (>300 lines):
  - [x] `tun.rs` (1,628 → 9 modules in tun/)
  - [x] `vpn_client.rs` (1,567 → 1,468 lines + vpn_common.rs)
  - [x] `vpn_server.rs` (1,517 → 1,448 lines)

### Documentation
- [x] Add doc comments to public API (all crate-level docs complete)
- [x] Create per-crate README files (9/9 complete)

---

## Short-term (P1)

### Testing
- [x] Add integration tests for full VPN flow (25 tests in tests/)
- [x] Add benchmarks with criterion (padding, replay, cover traffic)

### Security
- [x] Fix HACK markers (0 remaining - all were future feature TODOs)
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
