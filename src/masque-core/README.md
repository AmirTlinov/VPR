# MASQUE Core

Core VPN implementation using MASQUE protocol (RFC 9298) over HTTP/3.

## Features

- **MASQUE Protocol** - CONNECT-UDP over HTTP/3 (RFC 9298)
- **Post-Quantum** - ML-KEM768 hybrid key exchange
- **Stealth Mode** - TLS fingerprint mimicry (Chrome JA3/JA4)
- **Traffic Analysis Resistance** - Cover traffic, adaptive padding
- **Kill Switch** - WAL-based network guard

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       VPN Client                            │
│  ┌─────────┐  ┌──────────┐  ┌───────────────┐              │
│  │   TUN   │──│  Tunnel  │──│ Hybrid Noise  │              │
│  └─────────┘  └──────────┘  │  + ML-KEM768  │              │
│                             └───────┬───────┘              │
│                                     │                      │
│  ┌────────────────────────────────────────────────┐       │
│  │              MASQUE CONNECT-UDP                │       │
│  │                 (RFC 9298)                     │       │
│  └────────────────────┬───────────────────────────┘       │
│                       │                                    │
│  ┌────────────────────────────────────────────────┐       │
│  │          HTTP/3 over QUIC (h3-quinn)           │       │
│  └────────────────────┬───────────────────────────┘       │
└───────────────────────┼───────────────────────────────────┘
                        │ TLS 1.3 (Chrome fingerprint)
                        ↓
┌───────────────────────────────────────────────────────────┐
│                       VPN Server                          │
│  ┌─────────┐  ┌──────────┐  ┌──────────────────────┐     │
│  │   NAT   │──│ IP Pool  │──│ Noise + Key Rotation │     │
│  └─────────┘  └──────────┘  └──────────────────────┘     │
└───────────────────────────────────────────────────────────┘
```

## Security Features

| Feature | Description |
|---------|-------------|
| TLS Fingerprint | Mimics Chrome browser (JA3/JA4) |
| Cover Traffic | Background noise generation |
| Adaptive Padding | Packet size normalization |
| Domain Fronting | Optional CDN-based hiding |
| Probe Protection | Active probing defense |
| Key Rotation | 60s or 1GB threshold |
| Replay Protection | 5-minute window |

## Modules

| Module | Description |
|--------|-------------|
| `masque` | CONNECT-UDP protocol (RFC 9298) |
| `tunnel` | Encrypted tunnel implementation |
| `tun` | TUN device management |
| `network_guard` | Kill switch with WAL pattern |
| `key_rotation` | Automatic key rotation |
| `replay_protection` | Replay attack prevention |
| `tls_fingerprint` | Chrome fingerprint mimicry |
| `cover_traffic` | Traffic analysis resistance |
| `padding` | Packet size normalization |
| `hybrid_handshake` | Noise + ML-KEM768 |

## Quick Start

```rust
use masque_core::{VpnConfig, VpnTunnel};

let config = VpnConfig {
    server: "vpn.example.com:443".to_string(),
    noise_keypair_path: "secrets/client.noise".into(),
    server_pubkey_path: "secrets/server.noise.pub".into(),
    ..Default::default()
};

let tunnel = VpnTunnel::connect(config).await?;
```

## Testing

```bash
cargo test -p masque-core
```

## Binaries

- `vpn-client` - VPN client with TUN support
- `vpn-server` - VPN server with NAT
