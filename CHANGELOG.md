# Changelog

All notable changes to VPR will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-03

### Added
- Post-quantum hybrid cryptography (Noise IK + ML-KEM768 + X25519)
- MASQUE/QUIC transport (RFC 9298 compliant)
- TLS fingerprint mimicry (Chrome/Firefox profiles)
- AI Traffic Morpher for pattern obfuscation
- DoH/ODoH/DoQ gateway
- Cross-platform Kill Switch (Linux nftables, macOS pf, Windows WFP)
- TUI with ASCII Earth visualization
- Desktop application (Tauri-based)
- Health monitoring and diagnostics
- Probe protection and replay protection
- Automatic key rotation (60s/1GB)

### Security
- Replay cache hard limit to prevent memory exhaustion DoS
- Secure temp file creation with O_EXCL and O_NOFOLLOW flags
- State file integrity verification with SHA-256 checksums
- Fixed errno checking in process existence verification
- Session context binding for hybrid cryptographic secrets
- Panic-free key parsing with proper Result handling
- TOCTOU prevention in DNS configuration
- Integer overflow protection in IP pool allocation

## [0.1.0] - 2025-01-27

### Added
- Initial development release
- Core VPN functionality
- Basic cryptographic implementation
- Prototype MASQUE transport

---

Copyright (c) 2025 VPR Technologies. All Rights Reserved.
