#!/bin/bash
# VPR VPN App Diagnostic Script
# Safe, non-destructive analysis of why Tauri app fails to connect
# Does NOT modify network settings!

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo "========================================"
echo "   VPR VPN App Diagnostic Report"
echo "   $(date)"
echo "========================================"
echo ""

# ============================================
# 1. Binary checks
# ============================================
echo "=== 1. BINARY CHECKS ==="

VPR_ROOT="${VPR_ROOT:-$(dirname "$0")/..}"
cd "$VPR_ROOT"

if [[ -x "./target/debug/vpn-client" ]]; then
    log_pass "vpn-client binary exists and is executable"
    VPN_CLIENT="./target/debug/vpn-client"
else
    log_fail "vpn-client binary not found at ./target/debug/vpn-client"
    VPN_CLIENT=""
fi

if [[ -x "./target/debug/vpn-server" ]]; then
    log_pass "vpn-server binary exists and is executable"
else
    log_warn "vpn-server binary not found (optional for client testing)"
fi

if [[ -x "./target/debug/vpr-app" ]]; then
    log_pass "vpr-app (Tauri) binary exists"
else
    log_fail "vpr-app binary not found"
fi

echo ""

# ============================================
# 2. Configuration checks
# ============================================
echo "=== 2. CONFIGURATION CHECKS ==="

CONFIG_DIR="$HOME/.config/vpr"
CLIENT_CONFIG="$CONFIG_DIR/client/config.json"
SECRETS_DIR="$CONFIG_DIR/secrets"

if [[ -d "$CONFIG_DIR" ]]; then
    log_pass "Config directory exists: $CONFIG_DIR"
else
    log_fail "Config directory missing: $CONFIG_DIR"
fi

if [[ -f "$CLIENT_CONFIG" ]]; then
    log_pass "Client config exists: $CLIENT_CONFIG"
    log_info "Config contents:"
    cat "$CLIENT_CONFIG" | sed 's/^/       /'

    # Parse server from config
    SERVER=$(jq -r '.server // empty' "$CLIENT_CONFIG" 2>/dev/null || echo "")
    PORT=$(jq -r '.port // "443"' "$CLIENT_CONFIG" 2>/dev/null || echo "443")

    if [[ -n "$SERVER" ]]; then
        log_pass "Server configured: $SERVER:$PORT"
    else
        log_fail "No server configured in config.json"
    fi
else
    log_fail "Client config missing: $CLIENT_CONFIG"
    SERVER=""
    PORT=""
fi

echo ""

# ============================================
# 3. Secrets/Keys checks
# ============================================
echo "=== 3. SECRETS/KEYS CHECKS ==="

if [[ -d "$SECRETS_DIR" ]]; then
    log_pass "Secrets directory exists: $SECRETS_DIR"
else
    log_fail "Secrets directory missing: $SECRETS_DIR"
    log_info "Run: bash scripts/gen-noise-keys.sh $SECRETS_DIR"
fi

check_key() {
    local name="$1"
    local path="$SECRETS_DIR/$name"
    if [[ -f "$path" ]]; then
        local size=$(stat -c%s "$path" 2>/dev/null || echo 0)
        if [[ "$size" -eq 32 ]]; then
            log_pass "$name exists (32 bytes - correct)"
        else
            log_fail "$name wrong size: $size bytes (expected 32)"
        fi
    else
        log_fail "$name missing"
    fi
}

check_key "client.noise.key"
check_key "client.noise.pub"
check_key "server.noise.pub"

echo ""

# ============================================
# 4. vpn-client argument validation (DRY RUN)
# ============================================
echo "=== 4. VPN-CLIENT ARGUMENT VALIDATION ==="

if [[ -n "$VPN_CLIENT" && -n "$SERVER" ]]; then
    # Construct the same arguments that Tauri would use
    ARGS=(
        "--server" "${SERVER}:${PORT}"
        "--server-name" "$SERVER"
        "--tun-name" "vpr0"
        "--noise-dir" "$SECRETS_DIR"
        "--noise-name" "client"
        "--server-pub" "$SECRETS_DIR/server.noise.pub"
        "--tls-profile" "chrome"
    )

    # Check if localhost -> should add --insecure
    if [[ "$SERVER" == "localhost" || "$SERVER" == "127.0.0.1" || "$SERVER" =~ ^127\. ]]; then
        ARGS+=("--insecure")
        log_info "Localhost detected - --insecure flag needed"
    fi

    log_info "Command that would be executed:"
    echo "       $VPN_CLIENT ${ARGS[*]}"
    echo ""

    # Test with --help to validate arguments parse
    log_info "Testing argument parsing (--help)..."
    if $VPN_CLIENT --help >/dev/null 2>&1; then
        log_pass "vpn-client responds to --help"
    else
        log_fail "vpn-client --help failed"
    fi

    # Check if each required file exists
    if [[ ! -f "$SECRETS_DIR/server.noise.pub" ]]; then
        log_fail "--server-pub file does not exist!"
    fi
    if [[ ! -d "$SECRETS_DIR" ]]; then
        log_fail "--noise-dir directory does not exist!"
    fi
    if [[ ! -f "$SECRETS_DIR/client.noise.key" ]]; then
        log_fail "client.noise.key missing in --noise-dir"
    fi
else
    log_warn "Skipping argument validation (missing binary or config)"
fi

echo ""

# ============================================
# 5. Permission checks
# ============================================
echo "=== 5. PERMISSION CHECKS ==="

# TUN device requires CAP_NET_ADMIN or root
if [[ $EUID -eq 0 ]]; then
    log_pass "Running as root - TUN creation allowed"
else
    # Check if binary has capabilities
    if [[ -n "$VPN_CLIENT" ]]; then
        CAPS=$(getcap "$VPN_CLIENT" 2>/dev/null || echo "")
        if [[ "$CAPS" == *"cap_net_admin"* ]]; then
            log_pass "vpn-client has CAP_NET_ADMIN capability"
        else
            log_warn "vpn-client needs sudo or CAP_NET_ADMIN for TUN"
            log_info "Tauri app needs to run vpn-client with sudo"
        fi
    fi
fi

# Check if Tauri app tries to use sudo
if grep -q "sudo" "$VPR_ROOT/src/vpr-app/src/process_manager.rs" 2>/dev/null; then
    log_warn "process_manager.rs contains 'sudo' - check how it's used"
else
    log_info "process_manager.rs does not use sudo directly"
fi

# Check pkexec availability (polkit)
if command -v pkexec >/dev/null 2>&1; then
    log_pass "pkexec available for privilege escalation"
else
    log_warn "pkexec not available"
fi

echo ""

# ============================================
# 6. Network state (READ ONLY)
# ============================================
echo "=== 6. NETWORK STATE (read-only) ==="

log_info "Current TUN/VPN interfaces:"
ip link show 2>/dev/null | grep -E "vpr|tun" | sed 's/^/       /' || echo "       (none)"

log_info "Default route:"
ip route show default 2>/dev/null | head -1 | sed 's/^/       /' || echo "       (none)"

log_info "VPN-related processes:"
ps aux 2>/dev/null | grep -E "vpn-client|vpn-server|vpr-app" | grep -v grep | sed 's/^/       /' || echo "       (none running)"

echo ""

# ============================================
# 7. Server connectivity test (if configured)
# ============================================
echo "=== 7. SERVER CONNECTIVITY TEST ==="

if [[ -n "$SERVER" && -n "$PORT" ]]; then
    # DNS resolution
    log_info "Resolving $SERVER..."
    RESOLVED_IP=$(getent hosts "$SERVER" 2>/dev/null | awk '{print $1}' | head -1)
    if [[ -n "$RESOLVED_IP" ]]; then
        log_pass "DNS resolved: $SERVER -> $RESOLVED_IP"
    elif [[ "$SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_pass "Server is IP address: $SERVER"
        RESOLVED_IP="$SERVER"
    else
        log_fail "DNS resolution failed for $SERVER"
        RESOLVED_IP=""
    fi

    # TCP connectivity (QUIC uses UDP, but we can check if host is reachable)
    if [[ -n "$RESOLVED_IP" ]]; then
        log_info "Testing UDP port $PORT reachability..."
        # Use nc with timeout if available
        if command -v nc >/dev/null 2>&1; then
            if nc -zu -w2 "$RESOLVED_IP" "$PORT" 2>/dev/null; then
                log_pass "UDP port $PORT appears open (nc check)"
            else
                log_warn "UDP port $PORT may be filtered (nc check inconclusive for UDP)"
            fi
        fi

        # Simple ping test
        if ping -c 1 -W 2 "$RESOLVED_IP" >/dev/null 2>&1; then
            log_pass "Host $RESOLVED_IP is reachable (ping)"
        else
            log_warn "Host $RESOLVED_IP not responding to ping (may be filtered)"
        fi
    fi
else
    log_warn "Skipping connectivity test (no server configured)"
fi

echo ""

# ============================================
# 8. Tauri process_manager analysis
# ============================================
echo "=== 8. TAURI PROCESS MANAGER ANALYSIS ==="

PM_FILE="$VPR_ROOT/src/vpr-app/src/process_manager.rs"
if [[ -f "$PM_FILE" ]]; then
    log_info "Checking how Tauri spawns vpn-client..."

    # Check if it uses sudo
    if grep -q "Command::new.*sudo" "$PM_FILE" 2>/dev/null; then
        log_warn "Uses sudo in Command::new - may have permission issues"
    fi

    # Check stdout/stderr handling
    if grep -q "Stdio::piped" "$PM_FILE" 2>/dev/null; then
        log_info "stdout/stderr are piped (captured)"
    fi
    if grep -q "Stdio::null" "$PM_FILE" 2>/dev/null; then
        log_warn "Some stdio is set to null - may lose error output"
    fi

    # Check if stderr is actually read
    if grep -q "stderr" "$PM_FILE" 2>/dev/null; then
        log_pass "stderr is referenced in process_manager"
    else
        log_fail "stderr may not be captured/logged - errors will be silent!"
    fi

    # Check binary path resolution
    log_info "Binary path resolution:"
    grep -A5 "find_vpn_client_binary" "$PM_FILE" 2>/dev/null | head -10 | sed 's/^/       /'
else
    log_fail "process_manager.rs not found"
fi

echo ""

# ============================================
# 9. main.rs configuration analysis
# ============================================
echo "=== 9. MAIN.RS CONFIGURATION ANALYSIS ==="

MAIN_FILE="$VPR_ROOT/src/vpr-app/src/main.rs"
if [[ -f "$MAIN_FILE" ]]; then
    # Check secrets_dir construction
    log_info "Checking secrets_dir path construction..."
    if grep -q 'join("secrets")' "$MAIN_FILE" 2>/dev/null; then
        log_pass "secrets_dir includes 'secrets' subdirectory"
    else
        log_warn "secrets_dir may not include 'secrets' - check path!"
    fi

    # Check insecure flag logic
    log_info "Checking insecure flag logic..."
    if grep -q "is_localhost" "$MAIN_FILE" 2>/dev/null; then
        log_pass "localhost detection for insecure flag exists"
    else
        log_fail "No localhost detection - insecure may be hardcoded false!"
    fi

    # Check actual insecure value
    INSECURE_LINE=$(grep "insecure:" "$MAIN_FILE" 2>/dev/null | head -1)
    log_info "insecure field: $INSECURE_LINE"
else
    log_fail "main.rs not found"
fi

echo ""

# ============================================
# SUMMARY
# ============================================
echo "========================================"
echo "   DIAGNOSTIC SUMMARY"
echo "========================================"
echo -e "${GREEN}PASSED: $PASS${NC}"
echo -e "${RED}FAILED: $FAIL${NC}"
echo -e "${YELLOW}WARNINGS: $WARN${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Action required: Fix the FAILED items above${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "${YELLOW}Review warnings above${NC}"
    exit 0
else
    echo -e "${GREEN}All checks passed!${NC}"
    exit 0
fi
