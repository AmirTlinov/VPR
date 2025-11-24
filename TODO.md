# TODO

## 1. Project Scaffolding & Baseline
- [x] Initialize repo structure: `src/`, `infra/`, `docs/`
- [ ] Add base Nix environments for Rust components
- [ ] Define shared config schema (`config/vpr.yaml`) and sample secrets layout (`secrets/README`)
- [ ] Set up CI hooks (lint, fmt, tests) and pre-commit config

## 2. Cryptography & Identity
- [ ] Implement offline root CA generation script (Rust)
- [ ] Build `intermediate_ctl` tool for issuing node certs + Noise seeds
- [ ] Integrate `age`-based sealing for all artifacts; document key rotation policy
- [ ] Create KAT suite for NoiseIK/NK hybrids (X25519 + ML-KEM768)

## 3. MASQUE / Tunnel Core
- [ ] Prototype MASQUE CONNECT-UDP server (Rust/quinn) behind Caddy/nginx
- [ ] Add NoiseIK/NK handshake layer with adaptive padding buckets
- [ ] Implement session ticket rotation (≤60 s / 1 GB) + instrumentation hooks
- [ ] Integrate traffic-shaping module (trace-driven HTTP/3/WebRTC patterns)
- [ ] Add optional DPDK ingress path guarded by feature flag

## 4. DNS & Bootstrap Plane
- [ ] Implement hidden-master (home node) authoritative server with DNSSEC (ZSK weekly, KSK monthly)
- [ ] Build signed IXFR sync pipeline over WireGuard to VPS resolver
- [x] Develop ODoH/DoH/DoQ endpoints on VPS (Rust + quinn/quiche)
- [ ] Create moving-target DoH rotation job (ACME issuance + manifest update)
- [ ] Implement bootstrap manifest signer/validator and stego RSS publisher

## 5. Desktop Client (Tauri)
- [x] Create Tauri app structure with Rust backend
- [x] Implement settings UI (server, port, protocol, DoH endpoint)
- [x] Build connection status display with ASCII shield
- [x] Add session stats (time, upload, download)
- [ ] Integrate real masque-core connection logic
- [ ] Implement kill switch functionality
- [ ] Add auto-connect on startup
- [ ] Package for Linux (deb, rpm, AppImage)
- [ ] Package for macOS and Windows

## 6. Telemetry & Observability
- [x] Implement health-harness CLI for suspicion/jitter checks
- [ ] Implement lightweight agent exporting suspicion score, RTT, DoH/DoQ stats
- [ ] Add Prometheus-compatible endpoint (local-only)
- [ ] Build alerting rules for suspicion >0.35, bootstrap latency >3 s, DNS failures >1%
- [ ] Add log aggregation (structured JSON) per action, retained 30 days

## 7. Portable Edge Node
- [ ] Create Ansible role for miniPC deployment (MASQUE ingress + web cover + local ODoH)
- [ ] Implement Sync Content workflow (git fetch + rsync)
- [ ] Automate health beacon JSON publication to manifest
- [ ] Write failover drill script (simulate VPS block)

## 8. Testing & Validation
- [ ] Build network-namespace harness for non-disruptive tunnel tests
- [ ] Develop DPI lab scripts (adv padding, dMAP probes)
- [ ] Create chaos scenarios: packet loss bursts, QUIC block, DNS poisoning
- [ ] Document playbooks for monthly "mass-block chaos" exercise

## 9. Documentation & Ops
- [ ] Expand `1.logic` into full design doc (`docs/architecture.md`)
- [ ] Write user guide for desktop client
- [ ] Document disaster-recovery workflow (portable node promotion, key compromise)
- [ ] Prepare compliance checklist (crypto, secrets, logging)
