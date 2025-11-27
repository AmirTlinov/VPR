# DoH Gateway

Oblivious DNS over HTTPS (ODoH) gateway server.

## Features

- **ODoH Support** - RFC 9230 compliant
- **HTTP/3** - QUIC transport with h3
- **Auto TLS** - Certificate management
- **High Performance** - Async with Tokio

## What is ODoH?

Oblivious DNS over HTTPS hides the client IP from the DNS resolver:

```
Client → Target (encrypts query) → Relay → Target (decrypts, resolves)
         ^-- Client IP hidden --^
```

This gateway acts as the **Target** in the ODoH architecture.

## Quick Start

```bash
# Start gateway on default port
cargo run --bin doh-gateway

# With custom config
cargo run --bin doh-gateway -- \
  --http-listen 0.0.0.0:8053 \
  --quic-listen 0.0.0.0:8054 \
  --upstream 8.8.8.8:53
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--http-listen` | HTTP/HTTPS listen address (default: 0.0.0.0:8053) |
| `--quic-listen` | QUIC/HTTP3 listen address |
| `--upstream` | Upstream DNS resolver (default: 8.8.8.8:53) |
| `--cert` | TLS certificate path |
| `--key` | TLS private key path |
| `--config` | Config file path |

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/dns-query` | GET/POST | Standard DoH |
| `/odoh` | POST | ODoH encrypted queries |
| `/.well-known/odohconfigs` | GET | ODoH public key config |

## Configuration

```toml
[server]
http_listen = "0.0.0.0:8053"
quic_listen = "0.0.0.0:8054"

[dns]
upstream = "8.8.8.8:53"
cache_size = 10000
cache_ttl = 300

[tls]
cert_path = "/etc/doh-gateway/cert.pem"
key_path = "/etc/doh-gateway/key.pem"
```

## Testing

```bash
# Test DoH
curl -H 'content-type: application/dns-message' \
  'https://localhost:8053/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'

# Test ODoH config
curl https://localhost:8053/.well-known/odohconfigs
```

## Security

- All DNS queries are encrypted
- Client IP not logged for ODoH queries
- Rate limiting supported
- DNSSEC validation (optional)
