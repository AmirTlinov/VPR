#!/bin/bash
# VPR VPN App FULL Diagnostic Script
# Comprehensive, deterministic analysis
# Does NOT modify network settings!

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
CRITICAL=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
log_critical() { echo -e "${RED}[CRITICAL]${NC} $1"; ((CRITICAL++)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_section() { echo -e "\n${MAGENTA}=== $1 ===${NC}"; }

VPR_ROOT="${VPR_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$VPR_ROOT"

echo "========================================"
echo "   VPR VPN App FULL Diagnostic Report"
echo "   $(date)"
echo "   Root: $VPR_ROOT"
echo "========================================"

# ============================================
log_section "1. ENVIRONMENT"
# ============================================

log_info "User: $(whoami) (UID: $EUID)"
log_info "Shell: $SHELL"
log_info "PWD: $(pwd)"

if [[ $EUID -eq 0 ]]; then
    log_warn "Running as root - some tests may behave differently"
fi

# Check required tools
for tool in jq pkexec ip grep sed awk; do
    if command -v $tool &>/dev/null; then
        log_pass "$tool available"
    else
        log_fail "$tool NOT available"
    fi
done

# ============================================
log_section "2. BINARY CHECKS"
# ============================================

check_binary() {
    local name="$1"
    local path="$2"

    if [[ ! -e "$path" ]]; then
        log_fail "$name: file not found at $path"
        return 1
    fi

    if [[ ! -f "$path" ]]; then
        log_fail "$name: not a regular file"
        return 1
    fi

    if [[ ! -x "$path" ]]; then
        log_fail "$name: not executable"
        return 1
    fi

    # Check if it's a valid ELF binary
    if file "$path" | grep -q "ELF"; then
        log_pass "$name: valid ELF binary"
    else
        log_warn "$name: not an ELF binary ($(file -b "$path" | head -c 50))"
    fi

    # Check linked libraries
    local missing_libs=$(ldd "$path" 2>/dev/null | grep "not found" || true)
    if [[ -n "$missing_libs" ]]; then
        log_fail "$name: missing libraries:"
        echo "$missing_libs" | sed 's/^/       /'
        return 1
    else
        log_pass "$name: all libraries found"
    fi

    return 0
}

VPN_CLIENT="./target/debug/vpn-client"
VPN_SERVER="./target/debug/vpn-server"
VPR_APP="./target/debug/vpr-app"

check_binary "vpn-client" "$VPN_CLIENT"
check_binary "vpn-server" "$VPN_SERVER"
check_binary "vpr-app" "$VPR_APP"

# ============================================
log_section "3. CONFIGURATION FILES"
# ============================================

CONFIG_DIR="$HOME/.config/vpr"
CLIENT_CONFIG="$CONFIG_DIR/client/config.json"
SECRETS_DIR="$CONFIG_DIR/secrets"

# Directory structure
for dir in "$CONFIG_DIR" "$CONFIG_DIR/client" "$SECRETS_DIR"; do
    if [[ -d "$dir" ]]; then
        log_pass "Directory exists: $dir"
        log_info "  Permissions: $(stat -c '%a %U:%G' "$dir")"
    else
        log_fail "Directory missing: $dir"
    fi
done

# Config file
if [[ -f "$CLIENT_CONFIG" ]]; then
    log_pass "Config file exists: $CLIENT_CONFIG"

    # Validate JSON
    if jq empty "$CLIENT_CONFIG" 2>/dev/null; then
        log_pass "Config is valid JSON"

        # Extract and validate fields
        SERVER=$(jq -r '.server // empty' "$CLIENT_CONFIG")
        PORT=$(jq -r '.port // "443"' "$CLIENT_CONFIG")
        MODE=$(jq -r '.mode // "masque"' "$CLIENT_CONFIG")

        if [[ -n "$SERVER" ]]; then
            log_pass "server: $SERVER"
        else
            log_critical "server field is EMPTY!"
        fi

        log_info "port: $PORT"
        log_info "mode: $MODE"

        # Show full config
        log_info "Full config:"
        jq '.' "$CLIENT_CONFIG" 2>/dev/null | sed 's/^/       /'
    else
        log_fail "Config is INVALID JSON!"
        cat "$CLIENT_CONFIG" | sed 's/^/       /'
    fi
else
    log_critical "Config file MISSING: $CLIENT_CONFIG"
    SERVER=""
    PORT="443"
fi

# ============================================
log_section "4. CRYPTOGRAPHIC KEYS"
# ============================================

check_key_file() {
    local name="$1"
    local path="$2"
    local expected_size="$3"

    if [[ ! -f "$path" ]]; then
        log_fail "$name: file not found"
        return 1
    fi

    local size=$(stat -c%s "$path" 2>/dev/null)
    if [[ "$size" -eq "$expected_size" ]]; then
        log_pass "$name: correct size ($size bytes)"
    else
        log_fail "$name: wrong size ($size bytes, expected $expected_size)"
        return 1
    fi

    # Check permissions (should be restrictive for private keys)
    local perms=$(stat -c%a "$path")
    if [[ "$name" == *".key"* ]]; then
        if [[ "$perms" == "600" || "$perms" == "400" ]]; then
            log_pass "$name: secure permissions ($perms)"
        else
            log_warn "$name: permissions $perms (recommend 600)"
        fi
    fi

    # Check if file is readable
    if [[ -r "$path" ]]; then
        log_pass "$name: readable"
    else
        log_fail "$name: NOT readable by current user"
        return 1
    fi

    return 0
}

check_key_file "client.noise.key" "$SECRETS_DIR/client.noise.key" 32
check_key_file "client.noise.pub" "$SECRETS_DIR/client.noise.pub" 32
check_key_file "server.noise.pub" "$SECRETS_DIR/server.noise.pub" 32

# Optional server keys (for local testing)
if [[ -f "$SECRETS_DIR/server.noise.key" ]]; then
    check_key_file "server.noise.key" "$SECRETS_DIR/server.noise.key" 32
else
    log_info "server.noise.key not present (OK if using remote server)"
fi

# ============================================
log_section "5. VPN-CLIENT ARGUMENT SIMULATION"
# ============================================

if [[ -x "$VPN_CLIENT" && -n "$SERVER" ]]; then
    # Build exact command that Tauri would use
    ARGS=(
        "--server" "${SERVER}:${PORT}"
        "--server-name" "$SERVER"
        "--tun-name" "vpr0"
        "--noise-dir" "$SECRETS_DIR"
        "--noise-name" "client"
        "--server-pub" "$SECRETS_DIR/server.noise.pub"
        "--tls-profile" "chrome"
        "--set-default-route"
        "--dns-protection"
    )

    # Check localhost -> insecure
    IS_LOCALHOST=false
    if [[ "$SERVER" == "localhost" || "$SERVER" == "127.0.0.1" || "$SERVER" =~ ^127\. ]]; then
        IS_LOCALHOST=true
        ARGS+=("--insecure")
        log_info "Localhost detected -> --insecure will be added"
    fi

    log_info "Simulated command:"
    echo "       pkexec $VPN_CLIENT ${ARGS[*]}" | fold -w 80 -s | sed 's/^/       /'

    # Validate each argument's file/path exists
    log_info "Validating argument paths:"

    if [[ -d "$SECRETS_DIR" ]]; then
        log_pass "--noise-dir path exists"
    else
        log_fail "--noise-dir path does NOT exist!"
    fi

    if [[ -f "$SECRETS_DIR/server.noise.pub" ]]; then
        log_pass "--server-pub file exists"
    else
        log_critical "--server-pub file does NOT exist!"
    fi

    if [[ -f "$SECRETS_DIR/client.noise.key" ]]; then
        log_pass "client.noise.key exists (implied by --noise-name client)"
    else
        log_critical "client.noise.key missing!"
    fi

    # Test vpn-client can at least parse arguments (--help)
    log_info "Testing vpn-client --help..."
    if timeout 5 "$VPN_CLIENT" --help &>/dev/null; then
        log_pass "vpn-client responds to --help"
    else
        log_fail "vpn-client --help failed or timed out"
    fi

    # Check what --help says about required args
    log_info "Required arguments from --help:"
    "$VPN_CLIENT" --help 2>&1 | grep -E "required|REQUIRED|<.*>" | head -5 | sed 's/^/       /'
fi

# ============================================
log_section "6. PRIVILEGE ESCALATION (pkexec)"
# ============================================

if command -v pkexec &>/dev/null; then
    log_pass "pkexec binary found"
    log_info "pkexec path: $(which pkexec)"

    # Check polkit service
    if systemctl is-active polkit &>/dev/null; then
        log_pass "polkit service is running"
    elif pgrep -x polkitd &>/dev/null; then
        log_pass "polkitd process is running"
    else
        log_warn "polkit service status unknown"
    fi

    # Check if we have a polkit agent (needed for GUI prompts)
    if pgrep -f "polkit.*agent" &>/dev/null; then
        log_pass "polkit agent is running (GUI prompts will work)"
    else
        log_warn "No polkit agent detected - GUI password prompt may not appear"
        log_info "For GNOME: /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1"
        log_info "For KDE: /usr/lib/polkit-kde-authentication-agent-1"
    fi
else
    log_critical "pkexec NOT found - privilege escalation will fail!"
fi

# ============================================
log_section "7. PROCESS MANAGER CODE ANALYSIS"
# ============================================

PM_FILE="$VPR_ROOT/src/vpr-app/src/process_manager.rs"
if [[ -f "$PM_FILE" ]]; then
    log_pass "process_manager.rs found"

    # Check if pkexec is used
    if grep -q 'TokioCommand::new("pkexec")' "$PM_FILE"; then
        log_pass "Uses pkexec for privilege escalation"
    elif grep -q 'TokioCommand::new(&binary_path)' "$PM_FILE"; then
        log_critical "Launches vpn-client WITHOUT pkexec - will fail!"
    else
        log_warn "Could not determine how vpn-client is launched"
    fi

    # Check stderr handling
    if grep -q "Stdio::piped()" "$PM_FILE" | grep -q stderr; then
        log_pass "stderr is piped"
    fi

    # Check if errors are logged
    if grep -q "stderr" "$PM_FILE"; then
        log_info "stderr is referenced in code"
    else
        log_warn "stderr may not be captured"
    fi

    # Show the spawn code
    log_info "Spawn code snippet:"
    grep -A3 "TokioCommand::new" "$PM_FILE" | head -8 | sed 's/^/       /'
else
    log_fail "process_manager.rs not found"
fi

# ============================================
log_section "8. MAIN.RS CONFIGURATION ANALYSIS"
# ============================================

MAIN_FILE="$VPR_ROOT/src/vpr-app/src/main.rs"
if [[ -f "$MAIN_FILE" ]]; then
    log_pass "main.rs found"

    # Check secrets_dir construction
    log_info "secrets_dir construction:"
    grep -B2 -A5 'secrets_dir' "$MAIN_FILE" | grep -E "join|ProjectDirs|secrets" | head -5 | sed 's/^/       /'

    # Check insecure flag
    INSECURE_LINES=$(grep -n "insecure" "$MAIN_FILE" | head -5)
    log_info "insecure flag references:"
    echo "$INSECURE_LINES" | sed 's/^/       /'

    # Verify is_localhost check exists
    if grep -q "is_localhost" "$MAIN_FILE"; then
        log_pass "is_localhost check exists"
        grep -B1 -A1 "is_localhost" "$MAIN_FILE" | head -6 | sed 's/^/       /'
    else
        log_fail "is_localhost check MISSING - insecure may be hardcoded!"
    fi
else
    log_fail "main.rs not found"
fi

# ============================================
log_section "9. NETWORK STATE (read-only)"
# ============================================

log_info "Network interfaces:"
ip link show 2>/dev/null | grep -E "^[0-9]+:|state" | sed 's/^/       /'

log_info "TUN/VPN interfaces:"
TUN_INTERFACES=$(ip link show 2>/dev/null | grep -E "vpr|tun" || echo "(none)")
echo "$TUN_INTERFACES" | sed 's/^/       /'

log_info "Default routes:"
ip route show default 2>/dev/null | sed 's/^/       /' || echo "       (none)"

log_info "Routing table (main):"
ip route show table main 2>/dev/null | head -10 | sed 's/^/       /'

# Check if vpr0 already exists
if ip link show vpr0 &>/dev/null; then
    log_warn "vpr0 interface ALREADY EXISTS - may conflict"
else
    log_pass "vpr0 does not exist (clean state)"
fi

# ============================================
log_section "10. SERVER CONNECTIVITY"
# ============================================

if [[ -n "$SERVER" ]]; then
    # DNS resolution
    log_info "DNS resolution for $SERVER..."
    if [[ "$SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        RESOLVED_IP="$SERVER"
        log_pass "Server is already IP: $RESOLVED_IP"
    else
        RESOLVED_IP=$(getent hosts "$SERVER" 2>/dev/null | awk '{print $1}' | head -1)
        if [[ -n "$RESOLVED_IP" ]]; then
            log_pass "DNS: $SERVER -> $RESOLVED_IP"
        else
            log_fail "DNS resolution FAILED for $SERVER"
        fi
    fi

    if [[ -n "$RESOLVED_IP" ]]; then
        # Ping test
        if ping -c 1 -W 2 "$RESOLVED_IP" &>/dev/null; then
            log_pass "Ping to $RESOLVED_IP successful"
        else
            log_warn "Ping to $RESOLVED_IP failed (may be filtered)"
        fi

        # TCP port check (as fallback indicator)
        if timeout 3 bash -c "echo >/dev/tcp/$RESOLVED_IP/$PORT" 2>/dev/null; then
            log_pass "TCP port $PORT open on $RESOLVED_IP"
        else
            log_info "TCP port $PORT not responding (OK for QUIC-only server)"
        fi

        # Check if local server is running
        if [[ "$RESOLVED_IP" == "127.0.0.1" || "$SERVER" == "localhost" ]]; then
            if pgrep -f "vpn-server.*$PORT" &>/dev/null; then
                log_pass "Local vpn-server is running on port $PORT"
            elif ss -uln 2>/dev/null | grep -q ":$PORT "; then
                log_pass "Something is listening on UDP port $PORT"
            else
                log_critical "Local server NOT running on port $PORT!"
                log_info "Start with: sudo ./target/debug/vpn-server --bind 0.0.0.0:$PORT ..."
            fi
        fi
    fi
else
    log_warn "No server configured - skipping connectivity tests"
fi

# ============================================
log_section "11. RUNNING PROCESSES"
# ============================================

log_info "VPN-related processes:"
VPN_PROCS=$(ps aux 2>/dev/null | grep -E "vpn-client|vpn-server|vpr-app" | grep -v grep || echo "(none)")
echo "$VPN_PROCS" | sed 's/^/       /'

# Check for zombie or orphan TUN devices
log_info "TUN devices with no associated process:"
for tun in $(ip link show 2>/dev/null | grep -oE "(vpr[0-9]+|tun[0-9]+)" | sort -u); do
    # Try to find process using this interface
    OWNER=$(ip link show "$tun" 2>/dev/null | grep -oP 'link/\w+ \K\S+' || echo "unknown")
    log_info "  $tun - $OWNER"
done

# ============================================
log_section "12. DRY-RUN vpn-client (without network changes)"
# ============================================

if [[ -x "$VPN_CLIENT" ]]; then
    log_info "Testing vpn-client startup (will fail without TUN, but shows errors)..."

    # Run without sudo - should fail with permission error
    STDERR_OUTPUT=$("$VPN_CLIENT" \
        --server "${SERVER:-127.0.0.1}:${PORT:-4433}" \
        --server-name "${SERVER:-localhost}" \
        --server-pub "$SECRETS_DIR/server.noise.pub" \
        --noise-dir "$SECRETS_DIR" \
        --noise-name "client" \
        --tun-name "vpr-test-$$" \
        --insecure \
        2>&1 || true)

    EXIT_CODE=$?

    log_info "Exit code: $EXIT_CODE"
    log_info "Output (first 500 chars):"
    echo "$STDERR_OUTPUT" | head -c 500 | sed 's/^/       /'

    # Analyze the error
    if echo "$STDERR_OUTPUT" | grep -qi "permission denied\|operation not permitted\|EPERM"; then
        log_pass "Got permission error - expected without sudo/pkexec"
    elif echo "$STDERR_OUTPUT" | grep -qi "no such file\|not found"; then
        log_fail "Missing file error - check paths!"
    elif echo "$STDERR_OUTPUT" | grep -qi "invalid\|error\|failed"; then
        log_warn "Some error occurred - review output above"
    elif [[ $EXIT_CODE -eq 0 ]]; then
        log_warn "Unexpectedly succeeded (or didn't run)"
    fi
fi

# ============================================
log_section "13. TAURI-SPECIFIC CHECKS"
# ============================================

# Check Tauri config
TAURI_CONF="$VPR_ROOT/src/vpr-app/tauri.conf.json"
if [[ -f "$TAURI_CONF" ]]; then
    log_pass "tauri.conf.json exists"

    # Check security settings
    CSP=$(jq -r '.app.security.csp // "null"' "$TAURI_CONF" 2>/dev/null)
    log_info "CSP: $CSP"

    # Check window settings
    log_info "Window config:"
    jq '.app.windows[0] // empty' "$TAURI_CONF" 2>/dev/null | sed 's/^/       /'
else
    log_warn "tauri.conf.json not found"
fi

# Check for WebKit/GTK issues
if command -v pkg-config &>/dev/null; then
    if pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
        log_pass "webkit2gtk-4.1 available"
    elif pkg-config --exists webkit2gtk-4.0 2>/dev/null; then
        log_pass "webkit2gtk-4.0 available"
    else
        log_warn "webkit2gtk not found via pkg-config"
    fi
fi

# ============================================
log_section "14. KILLSWITCH/NFTABLES"
# ============================================

if command -v nft &>/dev/null; then
    log_pass "nft command available"

    # Check for existing VPR rules (read-only)
    if sudo -n nft list tables 2>/dev/null | grep -q vpr; then
        log_warn "VPR nftables rules already exist"
        sudo -n nft list table inet vpr_killswitch 2>/dev/null | head -10 | sed 's/^/       /'
    else
        log_pass "No existing VPR nftables rules"
    fi
else
    log_info "nft not available - killswitch may use iptables"
fi

# ============================================
# SUMMARY
# ============================================

echo ""
echo "========================================"
echo "   DIAGNOSTIC SUMMARY"
echo "========================================"
echo -e "${GREEN}PASSED:   $PASS${NC}"
echo -e "${YELLOW}WARNINGS: $WARN${NC}"
echo -e "${RED}FAILED:   $FAIL${NC}"
echo -e "${RED}CRITICAL: $CRITICAL${NC}"
echo ""

TOTAL_ISSUES=$((FAIL + CRITICAL))

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  CRITICAL ISSUES FOUND - WILL NOT WORK ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    exit 2
elif [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}FAILED items must be fixed before VPN will work${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "${YELLOW}Warnings should be reviewed${NC}"
    exit 0
else
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ALL CHECKS PASSED - READY TO CONNECT  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    exit 0
fi
