# VPR VPN Security Audit Report

**Date**: 2025-11-24
**Auditor**: Claude Code (Automated Security Review)
**Scope**: vpr-crypto, masque-core security modules
**Verdict**: **REQUEST_CHANGES**

---

## Summary

The VPR VPN system demonstrates solid cryptographic architecture with a hybrid post-quantum Noise handshake (X25519 + ML-KEM768), proper key management, and multiple defense-in-depth security layers. However, several issues require attention before production deployment.

---

## Risk Assessment Table

| Category | Risk Level | Findings |
|----------|------------|----------|
| Security | MEDIUM | 2 Major, 3 Minor issues |
| Correctness | LOW | 1 Minor issue |
| Performance | LOW | No significant concerns |
| Developer Experience | LOW | Good code organization |

---

## Gate Checklist

- [ ] **Tests**: Insufficient test coverage for security-critical edge cases
- [x] **Static Analysis**: Code structure is sound, no critical lint issues detected
- [ ] **Security**: Several issues identified (see Findings)
- [x] **Performance**: No obvious N+1 or allocation issues in hot paths
- [x] **Error Handling**: Generally good, but some information leakage concerns

---

## Findings

### BLOCKER (Must Fix Before Production)

None identified - no critical vulnerabilities that would allow immediate exploitation.

---

### MAJOR (High Priority)

#### M1. Non-Constant-Time Length Check in `ct_eq`
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/vpr-crypto/src/constant_time.rs:20-24`

```rust
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;  // EARLY RETURN LEAKS LENGTH INFO
    }
    a.ct_eq(b).into()
}
```

**Issue**: Early return on length mismatch leaks timing information about whether lengths match. An attacker can distinguish "wrong length" from "wrong content" by timing.

**Impact**: MEDIUM - Could aid in oracle attacks where input length is attacker-controlled.

**Recommendation**:
- For fixed-size secrets, use `ct_eq_32` or `ct_eq_64` which don't have this issue
- For variable-length comparisons, pad to maximum expected length or use XOR accumulator approach

---

#### M2. Generic `ct_select` Uses Branching
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/vpr-crypto/src/constant_time.rs:46-53`

```rust
pub fn ct_select<T: Copy>(condition: bool, a: T, b: T) -> T {
    // For generic types we use branching, but for primitives use ct_select_*
    if condition {
        a
    } else {
        b
    }
}
```

**Issue**: This function claims to be constant-time but uses conditional branching. The comment acknowledges this but the function name is misleading.

**Impact**: MEDIUM - If used with secret conditions, leaks timing information.

**Recommendation**:
- Rename to `select` (without `ct_` prefix) or mark as `#[deprecated]`
- Add documentation warning about non-constant-time behavior
- Consider removing to prevent accidental misuse

---

### MINOR (Should Fix)

#### m1. Replay Protection Hash Truncation
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/replay_protection.rs:205-213`

```rust
fn compute_hash(&self, message: &[u8]) -> NonceHash {
    let prefix_len = message.len().min(HASH_PREFIX_LEN);  // Only 128 bytes
    let mut hasher = Sha256::new();
    hasher.update(&message[..prefix_len]);
    let result = hasher.finalize();

    let mut hash = [0u8; 16];  // Truncated to 16 bytes
    hash.copy_from_slice(&result[..16]);
    hash
}
```

**Issue**:
1. Only first 128 bytes of message are hashed - messages differing only after byte 128 will hash identically
2. Hash truncated to 16 bytes (128 bits) - collision resistance reduced

**Impact**: LOW - 128-bit security is adequate for replay protection, but prefix limitation could be exploited if messages have common prefixes.

**Recommendation**:
- Increase `HASH_PREFIX_LEN` to 256 or hash entire message
- Consider 32-byte hash for full 256-bit security

---

#### m2. Potential Integer Overflow in Handshake Length
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/hybrid_handshake.rs:263`

```rust
let len = u32::from_be_bytes(len_buf) as usize;
```

**Issue**: On 32-bit platforms, `usize` is 32-bit so no issue. On 64-bit, large values could cause allocation issues. The check at line 267-268 mitigates this:

```rust
if len > 65536 {
    anyhow::bail!("handshake message too large: {len}");
}
```

**Impact**: LOW - Already mitigated, but check should come before the cast for defense in depth.

**Recommendation**: Validate length before casting to usize.

---

#### m3. Cover Traffic Marker is Predictable
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/cover_traffic.rs:181`

```rust
// Add cover traffic marker in first byte (for debugging)
data[0] = 0xCC; // Cover traffic marker
```

**Issue**: Cover traffic is identifiable by the `0xCC` first byte. While marked "for debugging", this should be disabled in production as it defeats traffic analysis resistance.

**Impact**: LOW - Reduces effectiveness of cover traffic against traffic analysis.

**Recommendation**:
- Make this configurable (disabled by default in production)
- Remove the marker entirely for production builds
- Use `#[cfg(debug_assertions)]` to conditionally include

---

#### m4. Unvalidated `noise_pubkey` in Manifest
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/vpr-crypto/src/manifest.rs:27`

```rust
pub struct ServerEndpoint {
    // ...
    /// Server's Noise public key (hex encoded)
    pub noise_pubkey: String,
    // ...
}
```

**Issue**: The `noise_pubkey` field is stored as a hex string but there's no validation that:
1. It's valid hex
2. It decodes to exactly 32 bytes
3. It's a valid X25519 public key point

**Impact**: LOW - Invalid keys would fail during handshake, but earlier validation provides better error messages and defense in depth.

**Recommendation**: Add validation in `ServerEndpoint::new()` or create a separate validation method.

---

### INFORMATIONAL (Suggestions)

#### I1. Missing `Zeroize` on Some Secret Types
**Files**: Various

The `HybridSecret.combined` is zeroized on drop, but intermediate buffers in `HybridSecret::combine()` (`ikm` Vec) are not explicitly zeroized:

```rust
pub fn combine(x25519: &[u8; 32], mlkem: &[u8]) -> Self {
    let mut ikm = Vec::with_capacity(32 + mlkem.len());
    ikm.extend_from_slice(x25519);
    ikm.extend_from_slice(mlkem);
    // ikm dropped here without zeroization
```

**Recommendation**: Use `Zeroizing<Vec<u8>>` for `ikm`.

---

#### I2. Error Messages Could Leak Timing
Error messages distinguish between different failure modes:
- "invalid ML-KEM ciphertext"
- "invalid ML-KEM public key"
- "message too short"

While acceptable for debugging, consider using generic error messages in production to prevent oracle attacks.

---

#### I3. Session Key Rotation Race Condition
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/key_rotation.rs`

`SessionKeyState::reset()` requires `&mut self`, but the struct uses `AtomicU64` for counters. There's potential for race conditions if reset is called while other threads are calling `record_bytes()`.

**Recommendation**: Consider using `AtomicU64::swap()` instead of `store()` in reset, or document the synchronization requirements.

---

#### I4. Probe Protection Challenge PoW is Weak
**File**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/probe_protection.rs:58`

Default difficulty of 2 (two leading zero bytes) requires ~65536 hashes on average. This is very lightweight and may not deter determined attackers.

**Recommendation**: Consider making difficulty configurable and recommend higher values (3-4 bytes) for high-security deployments.

---

## Positive Security Observations

### Well-Implemented Features

1. **Hybrid PQ Cryptography**: Correct implementation of X25519 + ML-KEM768 with proper HKDF key derivation. The domain separation string "VPR-Hybrid-KEM" is properly used.

2. **Key Zeroization**: Proper use of `zeroize` crate with `compiler_fence` to prevent optimization of sensitive data clearing.

3. **Random Number Generation**: Consistently uses `OsRng` for all cryptographic operations. Test instrumentation allows verification of RNG usage.

4. **File Permissions**: Private keys are saved with `0o600` permissions on Unix systems.

5. **Replay Protection**: Time-based expiration with configurable TTL prevents unbounded memory growth.

6. **Noise Protocol**: Correct use of `snow` crate with IK and NK patterns. Server identity is properly verified.

7. **Signed Manifests**: Ed25519 signatures with expiration checking prevent tampering and stale data.

8. **TLS Fingerprinting**: JA3 fingerprint mimicking for Chrome/Firefox/Safari aids in censorship circumvention.

9. **Input Validation**: Key sizes validated (32 bytes for X25519, 1184 for ML-KEM public, 1088 for ciphertext).

10. **No Hardcoded Secrets**: No API keys, passwords, or private keys found in source code.

---

## Dependency Analysis

### Cryptographic Dependencies (vpr-crypto)

| Dependency | Version | Notes |
|------------|---------|-------|
| x25519-dalek | 2.0 | Well-audited, constant-time |
| ed25519-dalek | 2.1 | Well-audited |
| snow | 0.9 | Noise protocol implementation |
| pqcrypto-mlkem | 0.1 | ML-KEM (Kyber) PQ KEM |
| sha2 | 0.10 | RustCrypto, well-maintained |
| hkdf | 0.12 | RustCrypto |
| age | 0.10 | Modern encryption |
| subtle | 2.6 | Constant-time operations |
| zeroize | 1.8 | Memory zeroization |

**Note**: `cargo audit` could not be run (advisory DB fetch failed). Manual review shows no known vulnerable versions in Cargo.toml.

---

## Unsafe Code Analysis

### Found `unsafe` Blocks

1. **`/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/vpr-crypto/src/constant_time.rs:138`**
   ```rust
   unsafe {
       std::ptr::write_volatile(byte, 0);
   }
   ```
   **Justification**: Correct use for zeroization. `write_volatile` prevents compiler optimization.
   **Verdict**: ACCEPTABLE

2. **`/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/tun.rs:401`**
   ```rust
   let euid = unsafe { libc::geteuid() };
   ```
   **Justification**: FFI call to get effective user ID for permission checking.
   **Verdict**: ACCEPTABLE

---

## Security Score

**Overall Score: 78/100**

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Cryptographic Correctness | 85/100 | 30% | 25.5 |
| Input Validation | 80/100 | 20% | 16.0 |
| Error Handling | 75/100 | 15% | 11.25 |
| Memory Safety | 90/100 | 15% | 13.5 |
| Secret Management | 80/100 | 10% | 8.0 |
| Defense in Depth | 70/100 | 10% | 7.0 |
| **Total** | | | **78.25** |

**Breakdown**:
- Strong cryptographic foundation (-5 for ct_select issue)
- Good input validation (-5 for missing manifest key validation)
- Error messages could aid attackers (-5)
- Excellent memory safety, minimal unsafe
- Secret zeroization mostly good (-5 for intermediate buffer)
- Multiple security layers but some gaps (-10 for cover traffic marker, weak PoW)

---

## Recommendations Summary

### Priority 1 (Before Production)
1. Fix or rename `ct_select<T>` to prevent misuse
2. Document length-comparison timing leak in `ct_eq`
3. Remove or make cover traffic marker configurable

### Priority 2 (Near-Term)
4. Add `noise_pubkey` validation in manifest
5. Zeroize intermediate `ikm` buffer in `HybridSecret::combine`
6. Increase replay hash prefix length

### Priority 3 (Enhancement)
7. Consider higher default PoW difficulty
8. Add generic error messages for production builds
9. Document session key rotation synchronization requirements

---

## Files Reviewed

### vpr-crypto/src/
- [x] noise.rs (483 lines)
- [x] constant_time.rs (228 lines)
- [x] keys.rs (291 lines)
- [x] manifest.rs (387 lines)
- [x] lib.rs (14 lines)
- [x] rng.rs (95 lines)
- [x] seal.rs (211 lines)
- [x] pki.rs (264 lines)
- [x] error.rs (52 lines)

### masque-core/src/
- [x] replay_protection.rs (356 lines)
- [x] probe_protection.rs (495 lines)
- [x] key_rotation.rs (486 lines)
- [x] padding.rs (317 lines)
- [x] cover_traffic.rs (383 lines)
- [x] tls_fingerprint.rs (492 lines)
- [x] hybrid_handshake.rs (375 lines)
- [x] domain_fronting.rs (466 lines)
- [x] noise_keys.rs (34 lines)
- [x] rng.rs (101 lines)

---

## Verdict

**REQUEST_CHANGES**

The codebase demonstrates strong security architecture and good cryptographic practices. However, the constant-time comparison issues (M1, M2) and the cover traffic marker (m3) should be addressed before production deployment to a high-security environment.

For lower-risk deployments, these issues represent defense-in-depth concerns rather than exploitable vulnerabilities, and the code could be deployed with documented limitations.
