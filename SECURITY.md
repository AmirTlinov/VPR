# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

### Contact

For security-related issues, please use GitHub's private vulnerability reporting feature
or contact the maintainers directly.

### Response Timeline

- **Initial response**: 48 hours
- **Status update**: 7 days
- **Critical fixes**: 24-48 hours

## Security Measures

### Cryptography

- **Key Exchange**: ML-KEM768 + X25519 hybrid (post-quantum resistant)
- **Symmetric Encryption**: ChaCha20-Poly1305
- **Random Number Generation**: OsRng (cryptographically secure)
- **Key Derivation**: HKDF with SHA-256

### Protocol Security

- **Noise Protocol Framework**: IK pattern for mutual authentication
- **TLS Fingerprint Randomization**: Evades deep packet inspection
- **Replay Protection**: Sliding window with bloom filter
- **Probe Protection**: DoS mitigation for malformed packets

### Memory Safety

- **Zeroizing**: All secret keys are zeroized on drop
- **Unsafe Blocks**: Documented and minimized
- **Rust Memory Safety**: No use-after-free, no buffer overflows

### Network Security

- **QUIC/MASQUE**: Modern transport with built-in encryption
- **DoH/ODoH**: Encrypted DNS queries
- **Kill Switch**: Prevents traffic leaks when VPN disconnects

## Dependencies

Security-critical dependencies are pinned to known-good versions:

- `snow` = "0.9.6" (Noise Protocol)
- `ml-kem` = "0.1" (Post-quantum KEM)
- `x25519-dalek` = "2" (Elliptic curve DH)
- `chacha20poly1305` = "0.10" (AEAD cipher)

Run `cargo audit` regularly to check for known vulnerabilities.
