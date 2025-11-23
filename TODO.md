# TODO

## 1. Project Scaffolding & Baseline
- [x] Initialize repo structure: `src/`, `infra/`, `gui/`, `docs/`, `.agents/`
- [ ] Add base Nix/Poetry environments for Rust+Python components
- [ ] Define shared config schema (`config/vpr.yaml`) and sample secrets layout (`secrets/README`)
- [ ] Set up CI hooks (lint, fmt, tests) and pre-commit config

## 2. Cryptography & Identity
- [ ] Implement offline root CA generation script (Rust or Go)
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

## 5. vpr Studio (Python GUI)
- [x] Scaffold PySide6 app structure with tabs: Deploy, Rotate, Failover, Health, Logs
- [ ] Implement state store (`~/.vpr/state.json`) with age-signed updates
- [x] Build Deploy wizard: user inputs login/IP/password (or SSH key), presses `Setup Node`, GUI auto-installs dependencies, runs Terraform/Ansible, and displays progress/logs
- [x] Implement Rotate Fronts/DoH actions with ACME, nginx reload, manifest push (single button per action)
- [x] Build Swap Node workflow (DNS update, manifest publish, drain monitor) triggered by one click
- [ ] Add Sync Content + Cleanup utilities (rsync + log pruning) with confirmation dialogs
- [x] Create Health dashboard (suspicion, RTT, DoH/DoQ status) + рекомендации/горячие действия
- [ ] Package GUI (PyInstaller or Briefcase) for Linux/macOS

## 6. Telemetry & Observability
- [x] Implement lightweight GUI health harness + history CLI for suspicion/jitter
- [ ] Implement lightweight agent exporting suspicion score, RTT, DoH/DoQ stats
- [ ] Add Prometheus-compatible endpoint (local-only) and GUI charts
- [ ] Build alerting rules for suspicion >0.35, bootstrap latency >3 s, DNS failures >1%
- [ ] Add log aggregation (structured JSON) per action, retained 30 days

## 7. Portable Edge Node
- [ ] Create Ansible role for miniPC deployment (MASQUE ingress + web cover + local ODoH)
- [ ] Implement Sync Content workflow (git fetch + rsync)
- [ ] Automate health beacon JSON publication to manifest
- [ ] Write failover drill script (simulate VPS block → Swap Node)

## 8. Testing & Validation
- [ ] Build network-namespace harness for non-disruptive tunnel tests
- [ ] Develop DPI lab scripts (adv padding, dMAP probes)
- [ ] Create chaos scenarios: packet loss bursts, QUIC block, DNS poisoning
- [ ] Document playbooks for monthly “mass-block chaos” exercise

## 9. Documentation & Ops
- [ ] Expand `1.logic` into full design doc (`docs/architecture.md`)
- [ ] Write operator guide for vpr Studio (deploy, rotate, swap, health)
- [ ] Document disaster-recovery workflow (portable node promotion, key compromise)
- [ ] Prepare compliance checklist (crypto, secrets, logging)
