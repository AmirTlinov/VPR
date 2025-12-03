# Security Policy

## Reporting Vulnerabilities

**Do NOT report security vulnerabilities through public channels.**

### Contact

For security-related issues, please contact our security team:

- **Email**: [security@vpr.tech](mailto:security@vpr.tech)
- **PGP Key**: Available at [vpr.tech/security/pgp](https://vpr.tech/security/pgp)

### Response Timeline

| Severity | Initial Response | Resolution Target |
|----------|------------------|-------------------|
| Critical | 4 hours | 24 hours |
| High | 24 hours | 72 hours |
| Medium | 48 hours | 7 days |
| Low | 7 days | 30 days |

Enterprise customers with SLA receive priority response times.

## Security Architecture

### Cryptography

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key Exchange | ML-KEM768 + X25519 | NIST FIPS 203 + RFC 7748 |
| Session Encryption | ChaCha20-Poly1305 | RFC 8439 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| Random Generation | OS CSPRNG | Platform native |

### Protocol Security

- **Noise Protocol Framework**: IK pattern with mutual authentication
- **Forward Secrecy**: Ephemeral keys with 60s/1GB rotation
- **Replay Protection**: Sliding window with 100K entry hard limit
- **Probe Protection**: Challenge-response against active probing

### Memory Safety

- **Secret Zeroization**: All keys zeroized on drop
- **Rust Memory Safety**: No buffer overflows, no use-after-free
- **Unsafe Minimization**: All unsafe blocks audited and documented

### Network Security

- **QUIC/MASQUE**: RFC 9298 compliant HTTP/3 tunneling
- **TLS Fingerprinting**: Browser profile mimicry
- **Kill Switch**: Atomic firewall rules with crash recovery
- **DNS Security**: DoH/ODoH/DoQ encrypted queries

## Bug Bounty

VPR operates a private bug bounty program for security researchers.

Contact [security@vpr.tech](mailto:security@vpr.tech) for program details and scope.

## Compliance

VPR undergoes regular security audits. Enterprise customers can request audit reports under NDA.

---

Copyright (c) 2025 VPR Technologies. All Rights Reserved.
