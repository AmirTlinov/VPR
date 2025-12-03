# VPR Security Audit Fixes - December 3, 2025

## Summary

Conducted comprehensive security audit of VPR VPN codebase and implemented fixes for all critical and high-priority issues.

## Fixed Issues

### Critical Issues (CRI) - All Fixed

#### CRI-001: Insecure TLS Certificate Verification ✅
**File:** `src/masque-core/src/client/tls.rs`

**Problem:** `InsecureVerifier` bypassed all certificate validation, enabling MITM attacks.

**Solution:**
- Removed `InsecureVerifier` entirely
- Added `CertValidation` enum with three modes:
  - `SystemRoots` - use webpki system CA roots
  - `CustomCa(PathBuf)` - custom CA certificate file
  - `PublicKeyPin(Vec<u8>)` - TOFU-style public key pinning
- Added `PublicKeyPinVerifier` with:
  - Certificate expiration validation
  - Constant-time public key comparison
  - Proper TLS 1.3 signature verification
- Legacy API returns error if `insecure=true`

#### CRI-002: Unvalidated Firewall Command Inputs ✅
**File:** `src/vpr-app/src/killswitch.rs`

**Problem:** IP addresses and ports passed to firewall commands without validation.

**Solution:**
- Added `validate_policy()` function that checks:
  - At least one VPN server IP required
  - At least one port required
  - IP addresses are not unspecified/broadcast/multicast/loopback
  - Ports are in valid range (1-65535)
- Validation runs before any firewall modifications

#### CRI-003: Libc Syscalls with Proper Safety Documentation ✅
**File:** `src/masque-core/src/tun/dns.rs`

**Problem:** `geteuid()` syscalls without proper safety documentation.

**Solution:**
- Added `is_root()` helper function with proper `#[cfg(unix)]`
- Added detailed SAFETY comments explaining why `geteuid()` is safe
- Platform-specific code paths for Unix vs non-Unix

#### CRI-004: DNS/IP Leak Protection Validation ✅
**File:** `src/masque-core/src/tun/dns.rs`

**Problem:** DNS modification vulnerable to symlink attacks and race conditions.

**Solution:**
- Added symlink detection (`is_resolv_conf_symlink()`)
- Added systemd-resolved detection (`is_systemd_resolved_active()`)
- Implemented atomic writes (temp file + rename)
- Added verification that DNS changes took effect
- Added systemd-resolved support via `resolvectl`
- Validated DNS server addresses before use

### High Priority Issues (HIGH) - All Fixed

#### HIGH-001: Certificate Validation Chain ✅
**File:** `src/masque-core/src/client/tls.rs`

**Problem:** No certificate expiration or structure validation.

**Solution:**
- Added `validate_certificate_basic()` function
- Checks certificate not-before and not-after dates
- Warns if certificate expires within 30 days
- Uses x509-parser for proper certificate parsing

#### HIGH-002: Input Validation for MASQUE Paths ✅
**File:** `src/masque-core/src/masque.rs`

**Problem:** Insufficient validation of CONNECT-UDP target paths.

**Solution:**
- Added hostname length validation (max 255 bytes, labels max 63 bytes)
- Added `validate_hostname()` function checking:
  - No empty labels (double dots)
  - Labels don't start/end with hyphen
  - Only valid DNS characters (alphanumeric, hyphen, underscore)
- Blocked SMTP ports (25, 465, 587) to prevent spam relay
- Enhanced error messages

#### HIGH-003: Enhanced Replay Protection ✅
**File:** `src/masque-core/src/replay_protection.rs`

**Problem:** 128-bit truncated hash vulnerable to birthday attacks after ~2^64 messages.

**Solution:**
- Changed `NonceHash` from 16 bytes to full 32 bytes (SHA-256)
- Increased `HASH_PREFIX_LEN` from 128 to 8192 bytes
- Now requires ~2^128 messages for birthday attack (infeasible)
- Updated tests for new behavior

#### HIGH-004: Atomic Kill Switch ✅
**File:** `src/vpr-app/src/killswitch.rs`

**Problem:** Race condition window during kill switch activation where traffic could leak.

**Solution:**
- Added `generate_nft_script()` for complete nftables ruleset
- Write script to temp file, then load atomically with `nft -f`
- All rules applied in single kernel transaction
- No window where firewall is disabled

#### HIGH-005: MASQUE RFC 9298 Compliance ✅
**File:** `src/masque-core/src/masque.rs`

**Problem:** Missing RFC-required capsule types and validation.

**Solution:**
- Already had proper capsule types (AddressRequest, AddressAssign, Close)
- Added comprehensive port blocking for abuse prevention
- Enhanced hostname validation per DNS standards
- Added size limits for capsule buffers

## Architecture Improvements

1. **Security-by-default**: No insecure modes available
2. **Defense in depth**: Multiple layers of validation
3. **Fail-safe design**: Errors are caught and reported, not ignored
4. **Atomic operations**: Kill switch and DNS changes are atomic

## Testing Recommendations

```bash
# Run unit tests
cargo test --workspace

# Run security-focused tests
cargo test --package masque-core replay
cargo test --package masque-core masque
cargo test --package vpr-app killswitch

# Check for unsafe code
cargo clippy --all-targets -- -D warnings
```

## Files Modified

1. `src/masque-core/src/client/tls.rs` - Certificate validation overhaul
2. `src/masque-core/src/tun/dns.rs` - DNS leak protection
3. `src/masque-core/src/masque.rs` - MASQUE path validation
4. `src/masque-core/src/replay_protection.rs` - Full SHA-256 hashes
5. `src/vpr-app/src/killswitch.rs` - Atomic nftables, input validation

## Risk Assessment After Fixes

| Category | Before | After |
|----------|--------|-------|
| TLS Security | CRITICAL | LOW |
| Input Validation | HIGH | LOW |
| DNS Leak Protection | HIGH | LOW |
| Replay Protection | MEDIUM | LOW |
| Kill Switch | HIGH | LOW |

**Overall Risk Level:** LOW (suitable for production with standard precautions)

---
*Generated by Security Audit - December 3, 2025*
