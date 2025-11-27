# VPR Crypto

Cryptographic primitives for VPR VPN with post-quantum security.

## Features

- **Hybrid Key Exchange** - X25519 + ML-KEM768 post-quantum resistant
- **Noise Protocol** - Authenticated key exchange (Noise_IK pattern)
- **Ed25519 Signatures** - Manifest and bootstrap signing
- **Age Encryption** - Secrets sealing for deployment
- **PKI Support** - X.509 certificate generation

## Architecture

```
vpr-crypto/
├── keys.rs          # Noise & signing keypairs
├── noise.rs         # Hybrid Noise + ML-KEM768 handshake
├── pki.rs           # X.509 certificate generation
├── seal.rs          # Age encryption for secrets
├── manifest.rs      # Signed manifest verification
├── constant_time.rs # Side-channel resistant operations
└── rng.rs           # Cryptographically secure RNG
```

## Quick Start

```rust
use vpr_crypto::{NoiseKeypair, SigningKeypair};
use std::path::Path;

// Generate Noise keypair for key exchange
let noise = NoiseKeypair::generate();
noise.save(Path::new("secrets"), "server")?;

// Generate signing keypair for manifests
let signing = SigningKeypair::generate();
let signature = signing.sign(b"data");
```

## Security Model

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Key Exchange | X25519 + ML-KEM768 | 128-bit classical, 192-bit quantum |
| Signatures | Ed25519 | 128-bit |
| Encryption | ChaCha20-Poly1305 | 256-bit |
| KDF | HKDF-SHA256 | 256-bit |

## Modules

| Module | Description |
|--------|-------------|
| `keys` | Noise and signing keypair management |
| `noise` | Hybrid post-quantum handshake |
| `pki` | X.509 certificate generation (ECDSA P-384) |
| `seal` | Age-based secrets encryption |
| `manifest` | Signed bootstrap manifest verification |
| `constant_time` | Timing-safe comparisons |
| `rng` | OS-level CSPRNG wrapper |

## Testing

```bash
cargo test -p vpr-crypto
```

## Dependencies

- `snow` - Noise protocol implementation
- `pqcrypto-mlkem` - ML-KEM768 post-quantum KEM
- `ed25519-dalek` - Ed25519 signatures
- `age` - Secrets encryption
- `rcgen` - X.509 certificate generation
