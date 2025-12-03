# VPR AI Agent System

Говори по русски.

## Цель проекта

Создание программы для туннелирования интернет соединения для создания неизвестного ультра-производительного, высокосекретного, безопасного протокола который нельзя было бы обнаружить или заблокировать. Который настраивался бы "одной кнопкой" на сервер и работал бы даже в Северной Корее, Татарстане, РФ, Китае и тд.

## Элитный Отряд Субагентов

Для flagship-качества разработки VPR создан специализированный набор AI-агентов. Каждый агент — эксперт в своём домене.

### Состав команды

| Агент | Специализация | Файл |
|-------|---------------|------|
| 🔐 **Crypto Sentinel** | PQ криптография, Noise protocol, key management | `.claude/commands/agents/crypto-sentinel.md` |
| 🎭 **DPI Evader** | ML evasion, traffic morphing, cover traffic | `.claude/commands/agents/dpi-evader.md` |
| 🚀 **Transport Architect** | MASQUE/QUIC, протоколы, производительность | `.claude/commands/agents/transport-architect.md` |
| 🛡️ **Security Auditor** | Threat modeling, code audit, vulnerabilities | `.claude/commands/agents/security-auditor.md` |
| ✅ **E2E Enforcer** | Integration testing, chaos engineering | `.claude/commands/agents/e2e-enforcer.md` |
| 🦀 **Rust Surgeon** | Rust код, clippy, performance, idioms | `.claude/commands/agents/rust-surgeon.md` |
| ⚙️ **Infra Ops** | Terraform, Ansible, one-button deployment | `.claude/commands/agents/infra-ops.md` |
| 🎯 **Stealth Orchestrator** | System coordination, threat response | `.claude/commands/agents/stealth-orchestrator.md` |
| 📚 **Doc Smith** | Documentation, ADRs, technical writing | `.claude/commands/agents/doc-smith.md` |

### Использование

Агенты активируются через slash-команды:
```
/agents/crypto-sentinel   — для криптографических задач
/agents/dpi-evader        — для задач маскировки трафика
/agents/transport-architect — для работы с MASQUE/QUIC
...
```

Полный индекс и примеры использования: `.claude/commands/agents/index.md`

## Архитектурные требования

- **Clarify constraints**: define threat model (state-level surveillance, DPI, active probing, traffic correlation), performance targets (Gbps per tunnel, acceptable latency), supported platforms, and "one-button" deployment scope
- **Map requirements to capabilities**: transport obfuscation, cryptographic assurances (forward secrecy, PQ readiness), network optimization, operational resilience
- **Survey existing building blocks**: WireGuard, MASQUE/HTTP3, QUIC, Noise-based handshakes
- **Design layered architecture**:
  - Covert bootstrap: pluggable transports (MASQUE over HTTPS/DoH, domain fronting)
  - Core tunnel: NoiseIK/NK + hybrid PQ-KEM + X25519, rotating session keys
  - Traffic shaping: adaptive cover traffic, mimic legitimate protocols (H3, WebRTC)
  - Performance plane: kernel bypass (DPDK/eBPF), multipath UDP
- **Build automation**: Terraform/Ansible, reproducible images
- **Threat-driven validation**: red-team DPI, active probe resistance, fuzzing

## Стандарты качества

Все агенты следуют единым стандартам VPR:

- Cyclomatic complexity ≤ 10
- Test coverage ≥ 85% по изменённому коду
- Никаких моков/фейков в продакшн коде
- Conventional Commits
- Документация обновляется вместе с кодом
