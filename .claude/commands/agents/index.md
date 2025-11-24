# VPR Elite Agent Squad

> *"An elite team of specialized AI agents for flagship-quality VPR development"*

## Quick Reference

| Agent | Domain | Invoke With |
|-------|--------|-------------|
| 🔐 **Crypto Sentinel** | PQ cryptography, Noise, keys | `/agents/crypto-sentinel` |
| 🎭 **DPI Evader** | ML evasion, traffic morphing | `/agents/dpi-evader` |
| 🚀 **Transport Architect** | MASQUE/QUIC, protocols | `/agents/transport-architect` |
| 🛡️ **Security Auditor** | Threat modeling, audits | `/agents/security-auditor` |
| ✅ **E2E Enforcer** | Integration, chaos testing | `/agents/e2e-enforcer` |
| 🦀 **Rust Surgeon** | Code quality, performance | `/agents/rust-surgeon` |
| ⚙️ **Infra Ops** | Terraform, Ansible, deploy | `/agents/infra-ops` |
| 🎯 **Stealth Orchestrator** | System coordination | `/agents/stealth-orchestrator` |
| 📚 **Doc Smith** | Documentation, ADRs | `/agents/doc-smith` |

## Agent Selection Guide

### By Task Type

```
Need to...                          → Use Agent
────────────────────────────────────────────────────
Fix cryptographic code              → Crypto Sentinel
Make traffic undetectable           → DPI Evader
Optimize QUIC/MASQUE performance    → Transport Architect
Review code for vulnerabilities     → Security Auditor
Write/fix E2E tests                 → E2E Enforcer
Fix Rust compilation/clippy         → Rust Surgeon
Automate deployment                 → Infra Ops
Coordinate multi-system changes     → Stealth Orchestrator
Write documentation                 → Doc Smith
```

### By Project Component

```
Component          Primary Agent        Support Agent
──────────────────────────────────────────────────────
vpr-crypto         Crypto Sentinel      Security Auditor
masque-core        Transport Architect  Crypto Sentinel
vpr-ai             DPI Evader           Stealth Orchestrator
vpr-app            Rust Surgeon         E2E Enforcer
infra/             Infra Ops            Security Auditor
docs/              Doc Smith            All
tests/             E2E Enforcer         Rust Surgeon
```

## Collaboration Patterns

### Security-Critical Change
```
1. Crypto Sentinel     → Implement crypto change
2. Security Auditor    → Review for vulnerabilities
3. E2E Enforcer        → Validate integration
4. Doc Smith           → Update security.md
```

### Stealth Improvement
```
1. DPI Evader          → Design evasion mechanism
2. Transport Architect → Integrate with MASQUE
3. Stealth Orchestrator → Coordinate rollout
4. E2E Enforcer        → Validate suspicion score
```

### New Feature Development
```
1. Stealth Orchestrator → Design coordination
2. Rust Surgeon         → Implement code
3. Security Auditor     → Security review
4. E2E Enforcer         → Integration tests
5. Doc Smith            → Documentation
```

### Emergency Response (DPI Detected)
```
1. Stealth Orchestrator → Assess situation
2. DPI Evader           → Propose countermeasure
3. Transport Architect  → Implement transport changes
4. Infra Ops            → Deploy to canary
5. E2E Enforcer         → Validate fix
```

## Quality Standards (All Agents)

Every agent adheres to these VPR flagship standards:

- **Code**: Cyclomatic complexity ≤10, test coverage ≥85%
- **Security**: No mocks/fakes in production, explicit error handling
- **Performance**: Measurable benchmarks, no unexplained regressions
- **Documentation**: Changes reflected in docs within same commit
- **Process**: Conventional commits, atomic changes, CI must pass

## Usage Examples

### Invoke an agent for a specific task:
```
User: I need to fix the replay protection window drift issue

Claude: Let me engage Crypto Sentinel for this cryptographic task...
[Reads /agents/crypto-sentinel]
[Applies crypto-sentinel expertise to the problem]
```

### Multi-agent collaboration:
```
User: The suspicion score spiked after the last deployment

Claude: This requires coordinated response. Engaging:
- Stealth Orchestrator for situation assessment
- DPI Evader to analyze traffic patterns
- E2E Enforcer to validate with tests
```

## Extending the Squad

To add a new agent:

1. Create `.claude/commands/agents/<name>.md`
2. Follow the template structure:
   - Expertise Domain
   - Primary Responsibilities
   - Working Principles
   - Key Files & Modules
   - Quality Standards
   - Commands Available
   - Response Format
   - Checklist
3. Add to this index
4. Update AGENTS.md (project root)

---

*Squad assembled for VPR flagship development. Each agent brings specialized expertise while sharing the common goal: undetectable, secure, performant VPN that works even in the harshest censorship environments.*
