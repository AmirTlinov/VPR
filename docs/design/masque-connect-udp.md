# MASQUE CONNECT-UDP Design Document

## Overview

This document describes the implementation of RFC 9298 (CONNECT-UDP) for VPR's masque-core server.

## Current State

masque-core currently implements:
- TLS/TCP + custom frame protocol + Noise_IK+ML-KEM768 handshake
- QUIC streams + custom frame protocol + Noise handshake
- Simple TCP/UDP proxy after tunnel establishment

## Target State

Implement proper MASQUE CONNECT-UDP:
- HTTP/3 server using h3 crate
- Extended CONNECT method with `:protocol: connect-udp`
- QUIC Datagrams for UDP payload encapsulation
- Capsule Protocol (RFC 9297) signaling
- Noise_IK+ML-KEM768 integration post-CONNECT

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         Client                                  │
├────────────────────────────────────────────────────────────────┤
│  1. QUIC Connection (TLS 1.3)                                  │
│  2. HTTP/3 Extended CONNECT (:protocol=connect-udp)            │
│  3. Noise_IK+ML-KEM768 Handshake (inside CONNECT tunnel)       │
│  4. UDP Datagrams via QUIC Datagrams                           │
└─────────────────────────┬──────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────────────┐
│                    masque-core Server                           │
├────────────────────────────────────────────────────────────────┤
│  HTTP/3 Layer (h3-quinn)                                       │
│    ├── CONNECT-UDP handler                                     │
│    │     ├── Parse target host:port from URI template          │
│    │     ├── Validate request (no localhost, etc.)             │
│    │     └── Return 200 OK + Capsule-Protocol: ?1              │
│    │                                                           │
│  Noise Layer (post-CONNECT)                                    │
│    ├── Noise_IK responder handshake                            │
│    └── ML-KEM768 hybrid key exchange                           │
│                                                                │
│  UDP Forwarding Layer                                          │
│    ├── QUIC Datagrams ←→ UDP socket                            │
│    └── Context ID = 0 for raw UDP payload                      │
└─────────────────────────┬──────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────────────┐
│                    Target UDP Service                           │
│                  (DNS, QUIC, games, etc.)                       │
└────────────────────────────────────────────────────────────────┘
```

## Protocol Flow

### 1. QUIC Connection Establishment
```
Client                                 Server
   │                                      │
   │──── QUIC Initial (TLS 1.3) ─────────>│
   │<─── QUIC Handshake ──────────────────│
   │──── QUIC Handshake Done ────────────>│
   │                                      │
```

### 2. HTTP/3 CONNECT-UDP Request
```
:method = CONNECT
:protocol = connect-udp
:scheme = https
:authority = proxy.example.com
:path = /.well-known/masque/udp/target.example.com/443/
```

### 3. Server Response (Success)
```
:status = 200
capsule-protocol = ?1
```

### 4. Noise Handshake (Inside Tunnel)
After CONNECT is established, client and server perform Noise_IK+ML-KEM768:
- Uses QUIC stream for handshake messages
- Derives hybrid shared secret

### 5. UDP Datagram Forwarding
```
QUIC Datagram Format:
┌─────────────────┬──────────────────────┐
│  Context ID (0) │  UDP Payload (var)   │
│   (varint)      │                      │
└─────────────────┴──────────────────────┘
```

## Implementation Plan

### Phase 1: HTTP/3 Infrastructure
1. Add h3 and h3-quinn dependencies
2. Create `masque.rs` module for CONNECT-UDP handling
3. Implement Extended CONNECT parser

### Phase 2: CONNECT-UDP Handler
1. Parse URI template (`/.well-known/masque/udp/{target}/{port}/`)
2. Validate target (no localhost, link-local, multicast)
3. Send 200 OK with `Capsule-Protocol: ?1`

### Phase 3: UDP Datagram Forwarding
1. Enable QUIC datagrams in transport config
2. Implement Context ID encoding/decoding
3. Create UDP socket and forward datagrams

### Phase 4: Noise Integration
1. Perform Noise handshake on CONNECT stream after 200 OK
2. All subsequent datagrams are Noise-encrypted
3. Hybrid PQ key derivation using ML-KEM768

## Dependencies

```toml
h3 = "0.0.6"
h3-quinn = "0.0.7"
bytes = "1.10"
```

## Testing

1. Unit tests for Context ID encoding
2. Integration test: DNS query through CONNECT-UDP
3. E2E test: Full tunnel with Noise encryption

## Security Considerations

1. **Target validation**: Reject localhost, link-local, multicast
2. **Rate limiting**: Limit datagrams per second
3. **Max datagram size**: 65,527 bytes per RFC
4. **Timeout**: Close idle tunnels after 2 minutes
