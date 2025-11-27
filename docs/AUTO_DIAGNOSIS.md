# VPN Auto-Diagnosis & Auto-Fix System

## Overview

Automatically detects and fixes common VPN connection issues without manual intervention.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 VPN Health Monitor                      │
├─────────────────────────────────────────────────────────┤
│  Pre-Connection Check → During Connection → Post-Fail   │
└─────────────────────────────────────────────────────────┘
```

## Detection Categories

### 1. **Network Layer** (Layer 3-4)
- ✅ Server reachability (ICMP/TCP/UDP)
- ✅ Port availability
- ✅ Routing table issues
- ✅ MTU problems

### 2. **Firewall Layer**
- ✅ UFW/iptables/nftables rules blocking traffic
- ✅ Kill switch conflicts
- ✅ Missing INPUT rules for server responses
- ✅ NAT/masquerade misconfigurations

### 3. **Cryptographic Layer**
- ✅ Certificate validation failures
- ✅ CA trust chain issues
- ✅ Noise protocol key mismatches
- ✅ Expired certificates

### 4. **System Layer**
- ✅ TUN/TAP kernel module missing
- ✅ Insufficient privileges (not root)
- ✅ DNS resolution failures
- ✅ Orphaned network state from crashes

## Auto-Fix Strategies

### ✅ Fully Automatic (No Confirmation)
1. **Flush DNS cache**
2. **Load TUN kernel module**
3. **Clean orphaned network state**
4. **Adjust MTU automatically**

### ⚠️ Semi-Automatic (Ask First)
1. **Open firewall ports** (`ufw allow 443/udp`)
2. **Upload client pubkey to server**
3. **Download new server certificate**
4. **Regenerate Noise keys**

### ❌ Manual Only (Too Risky)
1. **Modify system routing table**
2. **Change DNS servers**
3. **Disable kill switch permanently**

## Real-World Examples

### Example 1: UDP Port Blocked (Current Bug Fix)
```
Problem: QUIC timeout
├─ TCP works → Server alive ✓
├─ UDP fails → Firewall blocking
└─ Fix: ssh server 'ufw allow 443/udp' ✓
```

### Example 2: Noise Key Mismatch (Current Issue)
```
Problem: Hybrid handshake timeout
├─ QUIC works ✓
├─ Client keys exist ✓
├─ Server has old client.pub ✗
└─ Fix: scp client.pub → server ✓
```

### Example 3: Certificate Problem
```
Problem: TLS UnknownIssuer
├─ Server cert is self-signed
├─ Client doesn't have CA cert
└─ Fix: Download server.crt from server ✓
```

### Example 4: Kill Switch Blocking Response
```
Problem: Connection timeout with kill switch
├─ OUTPUT rules exist ✓
├─ INPUT rules missing ✗
└─ Fix: Add INPUT rules for saddr/sport ✓
```

## Implementation

### Phase 1: Detection (✓ Implemented)
- Pre-connection checks
- Error pattern matching
- Diagnostic probes

### Phase 2: Analysis (In Progress)
- Root cause identification
- Fix recommendation engine
- Risk assessment

### Phase 3: Auto-Fix (Planned)
- Safe fixes (automatic)
- Risky fixes (ask first)
- Server-side coordination

## Usage

### From Code
```rust
use masque_core::diagnostics::client;

let config = DiagnosticConfig {
    auto_fix: true,
    server_addr: Some((server_ip, 443)),
    privileged: true,
    ..Default::default()
};

let report = client::run_diagnostics(&config).await?;

if report.overall_status != HealthStatus::Healthy {
    eprintln!("Issues found:");
    for issue in report.failures() {
        eprintln!("  ❌ {}: {}", issue.check_name, issue.message);

        if issue.auto_fixable && config.auto_fix {
            eprintln!("  → Applying fix...");
            apply_fix(&issue.fix).await?;
        }
    }
}
```

### From CLI
```bash
# Run diagnostics
vpn-client --diagnose --server 64.176.70.203:443

# Run with auto-fix
vpn-client --diagnose --auto-fix --server 64.176.70.203:443
```

## Diagnostic Output Example

```
VPN Health Check Report
======================
Timestamp: 2025-11-27 03:00:00 UTC
Side: Client
Overall Status: ❌ Unhealthy

Checks:
  ✅ Noise Keys Present
  ⚠️  CA Certificate Present (using insecure mode)
  ✅ Server TCP Reachability (64.176.70.203:443)
  ❌ Server UDP Port Status (cannot verify - needs QUIC)
  ✅ DNS Resolution
  ℹ️  Kill Switch State (not active)
  ✅ Root Privileges
  ✅ TUN Device Support

Auto-Fixable Issues: 1
  ❌ Server UDP Port Status
     → Fix: Open UDP port 443 on server firewall

Recommended Actions:
  1. SSH to server: ufw allow 443/udp
  2. Download CA certificate: scp server:/path/to/server.crt secrets/
```

## Future Enhancements

1. **Machine Learning**: Learn common failure patterns over time
2. **Telemetry**: Send anonymous diagnostic data for improvement
3. **Self-Healing**: Automatically retry with different configs
4. **Health Dashboard**: Real-time monitoring UI
5. **Proactive Checks**: Periodic health checks even when connected
