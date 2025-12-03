# VPR - Post-Quantum Stealth VPN

[![Build Status](https://github.com/AmirTlinov/VPR/actions/workflows/ci.yml/badge.svg)](https://github.com/AmirTlinov/VPR/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

**VPR** is an enterprise-grade stealth VPN designed for hostile network environments. Built to bypass advanced DPI, censorship, and state-level surveillance with post-quantum cryptography.

## Features

| Feature | Description |
|---------|-------------|
| **Post-Quantum Security** | Hybrid Noise IK + ML-KEM768 + X25519 key exchange |
| **DPI Evasion** | TLS fingerprint mimicry (Chrome/Firefox), traffic morphing |
| **MASQUE Transport** | RFC 9298 compliant HTTP/3 tunneling over QUIC |
| **Kill Switch** | Atomic firewall rules with crash recovery |
| **AI Traffic Morpher** | Neural network for traffic pattern obfuscation |
| **Cross-Platform** | Linux, macOS, Windows support |

## Security

VPR implements defense-in-depth security:

- **256-bit Post-Quantum**: ML-KEM768 (NIST standard) + X25519 hybrid
- **Forward Secrecy**: Ephemeral keys with 60s/1GB rotation
- **Replay Protection**: 5-minute sliding window with hard limits
- **Probe Protection**: Challenge-response system against active probing
- **Zero Logging**: No user data collection or IP logging

## Subscription Plans

| Plan | Users | Devices | Support | Price |
|------|-------|---------|---------|-------|
| Personal | 1 | 5 | Email | $9.99/mo |
| Professional | 1 | 10 | Priority | $19.99/mo |
| Team | 10 | 50 | Dedicated | $99.99/mo |
| Enterprise | Unlimited | Unlimited | SLA | Contact us |

[Start Free Trial](https://vpr.tech/trial) | [Contact Sales](mailto:sales@vpr.tech)

## Quick Start

### Requirements

- Active VPR subscription
- Linux kernel 5.4+ / macOS 12+ / Windows 10+
- Root/Administrator privileges

### Installation

```bash
# Linux/macOS
curl -sSL https://get.vpr.tech | sh

# Or download from releases
wget https://releases.vpr.tech/latest/vpr-linux-amd64.tar.gz
tar xzf vpr-linux-amd64.tar.gz
sudo ./install.sh
```

### Connect

```bash
# Activate license
vpr activate YOUR-LICENSE-KEY

# Connect to optimal server
vpr connect

# Connect to specific region
vpr connect --region us-east

# Status
vpr status
```

### GUI Application

Download the desktop application from [vpr.tech/download](https://vpr.tech/download)

- Windows: `VPR-Setup.exe`
- macOS: `VPR.dmg`
- Linux: `vpr-desktop.AppImage`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    VPR Client                           │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   Desktop   │  │  Terminal   │  │   CLI Tools     │  │
│  │   (Tauri)   │  │   (TUI)     │  │                 │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         └────────────────┼──────────────────┘           │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │              VPN Core Engine                       │  │
│  │  ┌─────────┐ ┌──────────┐ ┌───────────────────┐   │  │
│  │  │ Traffic │ │ MASQUE   │ │ Post-Quantum      │   │  │
│  │  │ Morpher │ │ (HTTP/3) │ │ Noise + ML-KEM    │   │  │
│  │  └─────────┘ └──────────┘ └───────────────────┘   │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│  ┌───────────────────────▼───────────────────────────┐  │
│  │          TUN Device + Kill Switch                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                     QUIC/443 (TLS 1.3)
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    VPR Server                           │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐   │
│  │ Load        │ │ NAT/Routing  │ │ DoH Gateway     │   │
│  │ Balancer    │ │              │ │ (DNS over HTTPS)│   │
│  └─────────────┘ └──────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Technical design and components |
| [Security](docs/security.md) | Threat model and cryptographic details |
| [User Guide](docs/user-guide.md) | End-user documentation |
| [Disaster Recovery](docs/disaster-recovery.md) | Failover and recovery procedures |
| [Compliance](docs/compliance-checklist.md) | Security compliance checklist |

## Support

| Channel | Response Time | Availability |
|---------|---------------|--------------|
| [Documentation](https://docs.vpr.tech) | Instant | 24/7 |
| [Email Support](mailto:support@vpr.tech) | 24 hours | Business days |
| [Priority Support](mailto:priority@vpr.tech) | 4 hours | 24/7 |
| [Enterprise SLA](mailto:enterprise@vpr.tech) | 1 hour | 24/7 |

## Legal

**VPR is proprietary software.** Use requires a valid paid subscription.

See [LICENSE](LICENSE) for complete terms and conditions.

- Reverse engineering, decompilation, and redistribution are prohibited
- Commercial use requires enterprise licensing
- No warranty provided; use at your own risk

## About

VPR Technologies develops privacy-focused network security solutions for individuals and organizations operating in challenging network environments.

**Website**: [vpr.tech](https://vpr.tech)
**Email**: [contact@vpr.tech](mailto:contact@vpr.tech)
**Security**: [security@vpr.tech](mailto:security@vpr.tech)

---

Copyright (c) 2025 VPR Technologies. All Rights Reserved.
