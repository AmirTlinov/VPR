#!/bin/bash
# VPR VPN App ULTIMATE Diagnostic Script
# Maximum coverage - ALL edge cases
# Does NOT modify network settings!

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
CRITICAL=0

log_pass() { echo -e "${GREEN}[✓ PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "${RED}[✗ FAIL]${NC} $1"; ((FAIL++)); }
log_warn() { echo -e "${YELLOW}[! WARN]${NC} $1"; ((WARN++)); }
log_critical() { echo -e "${RED}[✗✗ CRITICAL]${NC} $1"; ((CRITICAL++)); }
log_info() { echo -e "${BLUE}[i INFO]${NC} $1"; }
log_section() { echo -e "\n${MAGENTA}══════════════════════════════════════════════════════════════${NC}"; echo -e "${MAGENTA}  $1${NC}"; echo -e "${MAGENTA}══════════════════════════════════════════════════════════════${NC}"; }
log_subsection() { echo -e "${CYAN}  ─── $1 ───${NC}"; }

VPR_ROOT="${VPR_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$VPR_ROOT"

CONFIG_DIR="$HOME/.config/vpr"
CLIENT_CONFIG="$CONFIG_DIR/client/config.json"
SECRETS_DIR="$CONFIG_DIR/secrets"
CERTS_DIR="$CONFIG_DIR/certs"

VPN_CLIENT="./target/debug/vpn-client"
VPN_SERVER="./target/debug/vpn-server"
VPR_APP="./target/debug/vpr-app"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       VPR VPN App ULTIMATE Diagnostic Report                 ║"
echo "║       $(date)                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ============================================
log_section "1. SYSTEM ENVIRONMENT"
# ============================================

log_subsection "Basic Info"
log_info "User: $(whoami) (UID: $EUID, GID: $(id -g))"
log_info "Groups: $(groups)"
log_info "Hostname: $(hostname)"
log_info "Kernel: $(uname -r)"
log_info "Arch: $(uname -m)"
log_info "Distro: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'unknown')"

log_subsection "Memory & Resources"
MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
MEM_AVAIL=$(free -m | awk '/^Mem:/{print $7}')
log_info "Memory: ${MEM_AVAIL}MB available / ${MEM_TOTAL}MB total"
if [[ $MEM_AVAIL -lt 100 ]]; then
    log_warn "Low memory available (<100MB)"
fi

log_subsection "Required Tools"
REQUIRED_TOOLS=(jq pkexec ip ss nft iptables grep sed awk timeout nc ping curl file ldd stat chmod)
for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_pass "$tool: $(which $tool)"
    else
        if [[ "$tool" == "nft" || "$tool" == "nc" ]]; then
            log_warn "$tool not found (optional)"
        else
            log_fail "$tool NOT found"
        fi
    fi
done

log_subsection "Kernel Modules"
if lsmod | grep -q "^tun "; then
    log_pass "TUN kernel module loaded"
else
    if [[ -c /dev/net/tun ]]; then
        log_pass "TUN device exists (module may be built-in)"
    else
        log_critical "TUN module NOT loaded and /dev/net/tun missing!"
    fi
fi

# Check /dev/net/tun permissions
if [[ -c /dev/net/tun ]]; then
    TUN_PERMS=$(stat -c '%a' /dev/net/tun)
    TUN_OWNER=$(stat -c '%U:%G' /dev/net/tun)
    log_info "/dev/net/tun: mode=$TUN_PERMS owner=$TUN_OWNER"
    if [[ -w /dev/net/tun ]]; then
        log_pass "/dev/net/tun is writable"
    else
        log_info "/dev/net/tun needs root (normal)"
    fi
else
    log_critical "/dev/net/tun does NOT exist!"
fi

log_subsection "IP Forwarding"
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
if [[ "$IP_FWD" == "1" ]]; then
    log_pass "IPv4 forwarding enabled"
else
    log_info "IPv4 forwarding disabled (OK for client, needed for server)"
fi

# ============================================
log_section "2. BINARY VALIDATION"
# ============================================

validate_binary() {
    local name="$1"
    local path="$2"

    log_subsection "$name"

    # Existence
    if [[ ! -e "$path" ]]; then
        log_critical "$name: file NOT found at $path"
        return 1
    fi

    # File type
    if [[ ! -f "$path" ]]; then
        log_fail "$name: not a regular file"
        return 1
    fi
    log_pass "$name: file exists"

    # Executable
    if [[ ! -x "$path" ]]; then
        log_fail "$name: not executable (chmod +x needed)"
        return 1
    fi
    log_pass "$name: executable"

    # File size
    local size=$(stat -c%s "$path")
    log_info "$name: size = $size bytes"
    if [[ $size -lt 1000 ]]; then
        log_warn "$name: suspiciously small (<1KB)"
    fi

    # ELF validation
    local filetype=$(file -b "$path")
    if echo "$filetype" | grep -q "ELF.*executable"; then
        log_pass "$name: valid ELF executable"
    elif echo "$filetype" | grep -q "ELF.*shared object"; then
        log_pass "$name: valid ELF shared object (PIE)"
    else
        log_warn "$name: unexpected file type: $filetype"
    fi

    # Architecture match
    if echo "$filetype" | grep -q "x86-64"; then
        if [[ "$(uname -m)" == "x86_64" ]]; then
            log_pass "$name: architecture matches system (x86_64)"
        else
            log_fail "$name: binary is x86_64 but system is $(uname -m)"
        fi
    fi

    # Library dependencies
    local missing_libs=$(ldd "$path" 2>&1 | grep "not found" || true)
    if [[ -n "$missing_libs" ]]; then
        log_critical "$name: MISSING libraries:"
        echo "$missing_libs" | sed 's/^/           /'
        return 1
    fi
    log_pass "$name: all libraries resolved"

    # Check for undefined symbols
    local undef_syms=$(nm -u "$path" 2>/dev/null | grep "U " | wc -l || echo "0")
    log_info "$name: $undef_syms undefined symbols (normal for dynamic linking)"

    # Security features
    if command -v checksec &>/dev/null; then
        log_info "$name: security features:"
        checksec --file="$path" 2>/dev/null | sed 's/^/           /' || true
    fi

    return 0
}

validate_binary "vpn-client" "$VPN_CLIENT"
validate_binary "vpn-server" "$VPN_SERVER"
validate_binary "vpr-app" "$VPR_APP"

# ============================================
log_section "3. CONFIGURATION VALIDATION"
# ============================================

log_subsection "Directory Structure"
REQUIRED_DIRS=("$CONFIG_DIR" "$CONFIG_DIR/client" "$SECRETS_DIR")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        perms=$(stat -c '%a' "$dir")
        owner=$(stat -c '%U:%G' "$dir")
        log_pass "Dir: $dir (mode=$perms, owner=$owner)"

        # Check if writable
        if [[ -w "$dir" ]]; then
            log_pass "  └─ writable by current user"
        else
            log_warn "  └─ NOT writable by current user"
        fi
    else
        log_fail "Dir MISSING: $dir"
    fi
done

log_subsection "Client Configuration"
if [[ -f "$CLIENT_CONFIG" ]]; then
    log_pass "Config exists: $CLIENT_CONFIG"

    # Validate JSON syntax
    JSON_ERROR=$(jq empty "$CLIENT_CONFIG" 2>&1)
    if [[ $? -eq 0 ]]; then
        log_pass "JSON syntax valid"
    else
        log_critical "JSON INVALID: $JSON_ERROR"
    fi

    # Extract fields with null checks
    SERVER=$(jq -r '.server // empty' "$CLIENT_CONFIG" 2>/dev/null)
    PORT=$(jq -r '.port // "443"' "$CLIENT_CONFIG" 2>/dev/null)
    MODE=$(jq -r '.mode // "masque"' "$CLIENT_CONFIG" 2>/dev/null)
    KILLSWITCH=$(jq -r '.killswitch // false' "$CLIENT_CONFIG" 2>/dev/null)
    AUTOCONNECT=$(jq -r '.autoconnect // false' "$CLIENT_CONFIG" 2>/dev/null)

    # Validate server
    if [[ -z "$SERVER" ]]; then
        log_critical "server field is EMPTY or missing!"
    elif [[ "$SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_pass "server: $SERVER (valid IPv4)"
    elif [[ "$SERVER" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_pass "server: $SERVER (hostname)"
    else
        log_warn "server: $SERVER (unusual format)"
    fi

    # Validate port
    if [[ "$PORT" =~ ^[0-9]+$ ]] && [[ "$PORT" -ge 1 ]] && [[ "$PORT" -le 65535 ]]; then
        log_pass "port: $PORT (valid)"
    else
        log_fail "port: $PORT (invalid)"
    fi

    # Mode validation
    case "$MODE" in
        masque|quic|wireguard)
            log_pass "mode: $MODE (supported)"
            ;;
        *)
            log_warn "mode: $MODE (unknown)"
            ;;
    esac

    log_info "killswitch: $KILLSWITCH"
    log_info "autoconnect: $AUTOCONNECT"

    # Edge case: empty strings that look truthy
    if [[ "$(jq -r '.server' "$CLIENT_CONFIG")" == "null" ]]; then
        log_critical "server is JSON null (not just empty)"
    fi

else
    log_critical "Config file MISSING: $CLIENT_CONFIG"
    SERVER=""
    PORT="443"
fi

# ============================================
log_section "4. CRYPTOGRAPHIC MATERIAL"
# ============================================

validate_key() {
    local name="$1"
    local path="$2"
    local expected_size="$3"
    local is_private="$4"

    log_subsection "$name"

    if [[ ! -e "$path" ]]; then
        log_critical "$name: FILE NOT FOUND"
        return 1
    fi

    if [[ ! -f "$path" ]]; then
        log_fail "$name: not a regular file"
        return 1
    fi

    # Size check
    local size=$(stat -c%s "$path" 2>/dev/null)
    if [[ "$size" -eq "$expected_size" ]]; then
        log_pass "$name: correct size ($size bytes)"
    elif [[ "$size" -eq 0 ]]; then
        log_critical "$name: FILE IS EMPTY!"
        return 1
    else
        log_fail "$name: wrong size ($size bytes, expected $expected_size)"
    fi

    # Permissions
    local perms=$(stat -c%a "$path")
    local owner=$(stat -c '%U:%G' "$path")
    log_info "$name: mode=$perms owner=$owner"

    if [[ "$is_private" == "true" ]]; then
        if [[ "$perms" == "600" || "$perms" == "400" ]]; then
            log_pass "$name: secure permissions"
        else
            log_warn "$name: insecure permissions (recommend 600)"
        fi
    fi

    # Readability
    if [[ -r "$path" ]]; then
        log_pass "$name: readable"
    else
        log_fail "$name: NOT readable"
        return 1
    fi

    # Content validation (check it's not all zeros or obviously wrong)
    local entropy=$(od -An -tx1 "$path" 2>/dev/null | tr -d ' \n' | fold -w2 | sort -u | wc -l)
    if [[ $entropy -lt 10 ]]; then
        log_warn "$name: low entropy (may be invalid key)"
    else
        log_pass "$name: appears to have good entropy"
    fi

    # Check for common mistakes
    if file "$path" | grep -qi "text\|ascii"; then
        log_warn "$name: appears to be text (keys should be binary)"
    fi

    return 0
}

validate_key "client.noise.key" "$SECRETS_DIR/client.noise.key" 32 "true"
validate_key "client.noise.pub" "$SECRETS_DIR/client.noise.pub" 32 "false"
validate_key "server.noise.pub" "$SECRETS_DIR/server.noise.pub" 32 "false"

# Optional keys
if [[ -f "$SECRETS_DIR/server.noise.key" ]]; then
    validate_key "server.noise.key" "$SECRETS_DIR/server.noise.key" 32 "true"
fi

# TLS certificates (for server)
log_subsection "TLS Certificates (optional)"
if [[ -d "$CERTS_DIR" ]]; then
    log_pass "Certs directory exists: $CERTS_DIR"

    for cert in "$CERTS_DIR"/*.crt "$CERTS_DIR"/*.pem; do
        [[ -f "$cert" ]] || continue
        log_info "Certificate: $(basename "$cert")"

        # Check expiry
        if command -v openssl &>/dev/null; then
            EXPIRY=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
            if [[ -n "$EXPIRY" ]]; then
                EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
                NOW_EPOCH=$(date +%s)
                DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

                if [[ $DAYS_LEFT -lt 0 ]]; then
                    log_critical "  Certificate EXPIRED!"
                elif [[ $DAYS_LEFT -lt 7 ]]; then
                    log_warn "  Expires in $DAYS_LEFT days"
                else
                    log_pass "  Valid for $DAYS_LEFT more days"
                fi
            fi
        fi
    done
else
    log_info "No certs directory (OK if using remote server)"
fi

# ============================================
log_section "5. PRIVILEGE ESCALATION"
# ============================================

log_subsection "pkexec"
if command -v pkexec &>/dev/null; then
    log_pass "pkexec found: $(which pkexec)"

    # Version
    PKEXEC_VER=$(pkexec --version 2>/dev/null || echo "unknown")
    log_info "pkexec version: $PKEXEC_VER"
else
    log_critical "pkexec NOT found!"
fi

log_subsection "polkit Service"
if systemctl is-active polkit &>/dev/null; then
    log_pass "polkit service: active"
elif systemctl is-active polkitd &>/dev/null; then
    log_pass "polkitd service: active"
elif pgrep -x polkitd &>/dev/null; then
    log_pass "polkitd process running"
else
    log_warn "polkit service status unclear"
fi

log_subsection "polkit Authentication Agent"
POLKIT_AGENTS=(
    "polkit-gnome-authentication-agent"
    "polkit-kde-authentication-agent"
    "polkit-mate-authentication-agent"
    "lxpolkit"
    "lxsession"
    "xfce-polkit"
    "polkit-agent"
)

AGENT_FOUND=false
for agent in "${POLKIT_AGENTS[@]}"; do
    if pgrep -f "$agent" &>/dev/null; then
        log_pass "polkit agent running: $agent"
        AGENT_FOUND=true
        break
    fi
done

if [[ "$AGENT_FOUND" == "false" ]]; then
    log_warn "No polkit agent detected!"
    log_info "  GUI password dialog may not appear"
    log_info "  Solutions:"
    log_info "    - GNOME: /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &"
    log_info "    - KDE: /usr/lib/polkit-kde-authentication-agent-1 &"
    log_info "    - Or run Tauri app with sudo"
fi

log_subsection "sudo Configuration"
if sudo -n true 2>/dev/null; then
    log_pass "sudo available without password (NOPASSWD or cached)"
else
    log_info "sudo requires password (normal)"
fi

# ============================================
log_section "6. NETWORK STATE (read-only)"
# ============================================

log_subsection "Interfaces"
IFACES=$(ip -o link show | awk -F': ' '{print $2}')
for iface in $IFACES; do
    STATE=$(ip -o link show "$iface" | grep -oP 'state \K\w+')
    log_info "  $iface: $STATE"
done

log_subsection "VPN/TUN Interfaces"
VPN_IFACES=$(ip link show 2>/dev/null | grep -E "vpr|tun|wg" | grep -oE "^[0-9]+: [^:@]+" | awk '{print $2}')
if [[ -n "$VPN_IFACES" ]]; then
    for iface in $VPN_IFACES; do
        IP_ADDR=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo "no IP")
        log_info "  $iface: $IP_ADDR"
    done
else
    log_info "  (no VPN interfaces)"
fi

# Check if vpr0 exists
if ip link show vpr0 &>/dev/null; then
    log_warn "vpr0 already exists - may cause conflicts!"
    ip addr show vpr0 2>/dev/null | sed 's/^/           /'
else
    log_pass "vpr0 does not exist (clean)"
fi

log_subsection "Routing"
log_info "Default routes:"
ip route show default 2>/dev/null | sed 's/^/           /'

# Check for route conflicts
if ip route show | grep -q "10.9.0.0/24"; then
    log_warn "Route to 10.9.0.0/24 already exists"
fi

log_subsection "DNS Configuration"
if [[ -f /etc/resolv.conf ]]; then
    DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    log_info "DNS servers: $DNS_SERVERS"

    # Check if systemd-resolved
    if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf | grep -q "systemd"; then
        log_info "Using systemd-resolved"
    fi
fi

log_subsection "Firewall State"
# iptables
if command -v iptables &>/dev/null; then
    IPTABLES_RULES=$(sudo -n iptables -L -n 2>/dev/null | wc -l || echo "0")
    log_info "iptables: ~$IPTABLES_RULES rules"
fi

# nftables
if command -v nft &>/dev/null; then
    NFT_TABLES=$(sudo -n nft list tables 2>/dev/null | wc -l || echo "0")
    log_info "nftables: $NFT_TABLES tables"

    if sudo -n nft list tables 2>/dev/null | grep -q "vpr"; then
        log_warn "VPR nftables rules already exist"
    fi
fi

# ============================================
log_section "7. SERVER CONNECTIVITY"
# ============================================

if [[ -n "$SERVER" ]]; then
    log_subsection "DNS Resolution"
    if [[ "$SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        RESOLVED_IP="$SERVER"
        log_pass "Already IP: $RESOLVED_IP"
    else
        # Try multiple DNS methods
        RESOLVED_IP=""

        # Method 1: getent
        RESOLVED_IP=$(getent hosts "$SERVER" 2>/dev/null | awk '{print $1}' | head -1)

        # Method 2: dig
        if [[ -z "$RESOLVED_IP" ]] && command -v dig &>/dev/null; then
            RESOLVED_IP=$(dig +short "$SERVER" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
        fi

        # Method 3: host
        if [[ -z "$RESOLVED_IP" ]] && command -v host &>/dev/null; then
            RESOLVED_IP=$(host "$SERVER" 2>/dev/null | grep "has address" | awk '{print $4}' | head -1)
        fi

        if [[ -n "$RESOLVED_IP" ]]; then
            log_pass "DNS resolved: $SERVER -> $RESOLVED_IP"
        else
            log_fail "DNS resolution FAILED for $SERVER"
        fi
    fi

    if [[ -n "$RESOLVED_IP" ]]; then
        log_subsection "Connectivity Tests"

        # Ping
        if ping -c 1 -W 2 "$RESOLVED_IP" &>/dev/null; then
            PING_MS=$(ping -c 1 -W 2 "$RESOLVED_IP" 2>/dev/null | grep -oP 'time=\K[0-9.]+' || echo "?")
            log_pass "Ping: ${PING_MS}ms"
        else
            log_info "Ping failed (may be filtered)"
        fi

        # UDP port (QUIC)
        if command -v nc &>/dev/null; then
            if timeout 2 nc -zu "$RESOLVED_IP" "$PORT" 2>/dev/null; then
                log_pass "UDP port $PORT: open"
            else
                log_info "UDP port $PORT: no response (normal for QUIC)"
            fi
        fi

        # TCP port (fallback check)
        if timeout 2 bash -c "echo >/dev/tcp/$RESOLVED_IP/$PORT" 2>/dev/null; then
            log_info "TCP port $PORT: open"
        fi

        log_subsection "Local Server Check"
        if [[ "$RESOLVED_IP" == "127.0.0.1" || "$SERVER" == "localhost" ]]; then
            # Check if server process running
            if pgrep -f "vpn-server" &>/dev/null; then
                log_pass "vpn-server process running"
                ps aux | grep "vpn-server" | grep -v grep | sed 's/^/           /'
            else
                log_critical "vpn-server NOT running!"
            fi

            # Check UDP socket
            if ss -uln 2>/dev/null | grep -q ":$PORT "; then
                log_pass "UDP socket listening on :$PORT"
            else
                log_critical "Nothing listening on UDP :$PORT"
            fi

            # Check if server TUN exists
            if ip link show vpr-srv0 &>/dev/null; then
                log_pass "Server TUN (vpr-srv0) exists"
            else
                log_warn "Server TUN (vpr-srv0) does not exist"
            fi
        fi
    fi
else
    log_warn "No server configured"
fi

# ============================================
log_section "8. CODE ANALYSIS"
# ============================================

log_subsection "process_manager.rs"
PM_FILE="$VPR_ROOT/src/vpr-app/src/process_manager.rs"
if [[ -f "$PM_FILE" ]]; then
    log_pass "File exists"

    # Check privilege escalation method
    if grep -q 'TokioCommand::new("pkexec")' "$PM_FILE"; then
        log_pass "Uses pkexec for privilege escalation"
    elif grep -q 'TokioCommand::new("sudo")' "$PM_FILE"; then
        log_warn "Uses sudo (may not work in GUI)"
    elif grep -q 'TokioCommand::new(&binary_path)' "$PM_FILE"; then
        log_critical "NO privilege escalation - will FAIL!"
    fi

    # Check stderr handling
    if grep -q "Stdio::piped" "$PM_FILE"; then
        if grep -q "stderr" "$PM_FILE"; then
            log_pass "stderr is captured"
        else
            log_warn "stderr piped but may not be logged"
        fi
    fi

    # Check for error handling
    ERROR_HANDLERS=$(grep -c "\.context\|\.map_err\|anyhow\|Error" "$PM_FILE" || echo "0")
    log_info "Error handling constructs: $ERROR_HANDLERS"
fi

log_subsection "main.rs"
MAIN_FILE="$VPR_ROOT/src/vpr-app/src/main.rs"
if [[ -f "$MAIN_FILE" ]]; then
    log_pass "File exists"

    # Check is_localhost logic
    if grep -q "is_localhost" "$MAIN_FILE"; then
        log_pass "is_localhost check exists"

        # Verify the logic
        if grep -E 'localhost.*127\.0\.0\.1|127\.0\.0\.1.*localhost' "$MAIN_FILE" &>/dev/null; then
            log_pass "Checks both 'localhost' and '127.0.0.1'"
        fi

        if grep -q 'starts_with("127.")' "$MAIN_FILE"; then
            log_pass "Checks 127.x.x.x range"
        fi
    else
        log_critical "is_localhost check MISSING!"
    fi

    # Check insecure flag assignment
    INSECURE_ASSIGNS=$(grep -n "insecure:" "$MAIN_FILE")
    log_info "insecure assignments:"
    echo "$INSECURE_ASSIGNS" | sed 's/^/           /'
fi

log_subsection "vpn_client.rs (masque-core)"
VPN_CLIENT_RS="$VPR_ROOT/src/masque-core/src/bin/vpn_client.rs"
if [[ -f "$VPN_CLIENT_RS" ]]; then
    log_pass "File exists"

    # Check required args
    REQUIRED_ARGS=$(grep -oP '#\[arg\(.*required.*\)\]' "$VPN_CLIENT_RS" | wc -l || echo "0")
    log_info "Required CLI args: $REQUIRED_ARGS"

    # Check TUN creation
    if grep -q "TunConfig\|create_tun\|tun::" "$VPN_CLIENT_RS"; then
        log_pass "TUN creation code present"
    fi
fi

# ============================================
log_section "9. ARGUMENT SIMULATION"
# ============================================

if [[ -x "$VPN_CLIENT" && -n "$SERVER" ]]; then
    log_subsection "Command Construction"

    # Build exact args
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

    IS_LOCALHOST=false
    if [[ "$SERVER" == "localhost" || "$SERVER" == "127.0.0.1" || "$SERVER" =~ ^127\. ]]; then
        IS_LOCALHOST=true
        ARGS+=("--insecure")
        log_info "Localhost -> adding --insecure"
    fi

    log_info "Full command:"
    echo "           pkexec $VPN_CLIENT \\"
    for arg in "${ARGS[@]}"; do
        echo "             $arg \\"
    done | sed '$ s/ \\$//'

    log_subsection "Path Validation"
    # Validate every path argument
    if [[ -d "$SECRETS_DIR" ]]; then
        log_pass "--noise-dir: exists"
    else
        log_critical "--noise-dir: DOES NOT EXIST"
    fi

    if [[ -f "$SECRETS_DIR/server.noise.pub" ]]; then
        log_pass "--server-pub: exists"
    else
        log_critical "--server-pub: DOES NOT EXIST"
    fi

    if [[ -f "$SECRETS_DIR/client.noise.key" ]]; then
        log_pass "client.noise.key: exists (for --noise-name client)"
    else
        log_critical "client.noise.key: MISSING"
    fi

    log_subsection "Dry-Run Test"
    # Run with invalid TUN name to test argument parsing without network changes
    TEST_OUTPUT=$("$VPN_CLIENT" --help 2>&1)
    if [[ $? -eq 0 ]]; then
        log_pass "vpn-client --help works"
    else
        log_fail "vpn-client --help failed"
    fi

    # Try to start but expect permission error
    log_info "Testing startup (expecting permission error)..."
    STDERR=$("$VPN_CLIENT" \
        --server "${SERVER}:${PORT}" \
        --server-name "$SERVER" \
        --server-pub "$SECRETS_DIR/server.noise.pub" \
        --noise-dir "$SECRETS_DIR" \
        --noise-name "client" \
        --tun-name "vpr-diag-$$" \
        --insecure \
        2>&1) || true

    if echo "$STDERR" | grep -qi "permission denied\|operation not permitted\|EPERM"; then
        log_pass "Got expected permission error (needs pkexec)"
    elif echo "$STDERR" | grep -qi "no such file\|not found"; then
        log_fail "Missing file error detected!"
        echo "$STDERR" | head -5 | sed 's/^/           /'
    elif echo "$STDERR" | grep -qi "connection refused\|unreachable"; then
        log_info "Connection error (server may be down)"
    else
        log_info "Output: $(echo "$STDERR" | head -3 | tr '\n' ' ')"
    fi
fi

# ============================================
log_section "10. EDGE CASES"
# ============================================

log_subsection "Path Edge Cases"

# Spaces in paths
if [[ "$VPR_ROOT" == *" "* ]]; then
    log_warn "Project root contains spaces: may cause issues"
fi

if [[ "$HOME" == *" "* ]]; then
    log_warn "HOME contains spaces: may cause issues"
fi

# Symlinks
if [[ -L "$VPN_CLIENT" ]]; then
    log_info "vpn-client is a symlink -> $(readlink -f "$VPN_CLIENT")"
fi

if [[ -L "$SECRETS_DIR" ]]; then
    log_info "secrets dir is a symlink -> $(readlink -f "$SECRETS_DIR")"
fi

# Unicode in paths
if echo "$VPR_ROOT" | grep -qP '[^\x00-\x7F]'; then
    log_warn "Non-ASCII characters in path (Cyrillic 'Документы')"
    log_info "  This may cause issues with some tools"
fi

log_subsection "Config Edge Cases"

if [[ -f "$CLIENT_CONFIG" ]]; then
    # Empty values that are not null
    if jq -e '.server == ""' "$CLIENT_CONFIG" &>/dev/null; then
        log_critical "server is empty string (not null)"
    fi

    # Whitespace
    SERVER_RAW=$(jq -r '.server' "$CLIENT_CONFIG")
    if [[ "$SERVER_RAW" != "$(echo "$SERVER_RAW" | xargs)" ]]; then
        log_warn "server has leading/trailing whitespace"
    fi

    # Port as number vs string
    PORT_TYPE=$(jq -r '.port | type' "$CLIENT_CONFIG" 2>/dev/null)
    log_info "port type: $PORT_TYPE"
fi

log_subsection "Process Edge Cases"

# Zombie vpn processes
ZOMBIES=$(ps aux | grep -E "vpn-client|vpn-server" | grep -E "Z|defunct" || true)
if [[ -n "$ZOMBIES" ]]; then
    log_warn "Zombie VPN processes found:"
    echo "$ZOMBIES" | sed 's/^/           /'
fi

# Multiple instances
VPN_CLIENT_COUNT=$(pgrep -c "vpn-client" 2>/dev/null || echo "0")
if [[ $VPN_CLIENT_COUNT -gt 1 ]]; then
    log_warn "Multiple vpn-client instances running ($VPN_CLIENT_COUNT)"
fi

log_subsection "Network Edge Cases"

# MTU issues
DEFAULT_MTU=$(ip link show | grep -oP 'mtu \K[0-9]+' | head -1 || echo "1500")
log_info "Default MTU: $DEFAULT_MTU"
if [[ $DEFAULT_MTU -lt 1400 ]]; then
    log_warn "Low MTU may cause fragmentation issues"
fi

# IPv6 state
IPV6_DISABLED=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
if [[ "$IPV6_DISABLED" == "1" ]]; then
    log_info "IPv6 disabled system-wide"
fi

# ============================================
log_section "11. RUNTIME PREDICTIONS"
# ============================================

log_subsection "Will Connection Work?"

WILL_WORK=true
BLOCKERS=()

# Check critical items
if [[ ! -x "$VPN_CLIENT" ]]; then
    BLOCKERS+=("vpn-client not executable")
    WILL_WORK=false
fi

if [[ -z "$SERVER" ]]; then
    BLOCKERS+=("No server configured")
    WILL_WORK=false
fi

if [[ ! -f "$SECRETS_DIR/server.noise.pub" ]]; then
    BLOCKERS+=("server.noise.pub missing")
    WILL_WORK=false
fi

if [[ ! -f "$SECRETS_DIR/client.noise.key" ]]; then
    BLOCKERS+=("client.noise.key missing")
    WILL_WORK=false
fi

if ! command -v pkexec &>/dev/null; then
    BLOCKERS+=("pkexec not available")
    WILL_WORK=false
fi

if ! grep -q 'TokioCommand::new("pkexec")' "$PM_FILE" 2>/dev/null; then
    BLOCKERS+=("Code doesn't use pkexec")
    WILL_WORK=false
fi

# Localhost-specific
if [[ "$SERVER" == "127.0.0.1" || "$SERVER" == "localhost" ]]; then
    if ! pgrep -f "vpn-server" &>/dev/null; then
        BLOCKERS+=("Local server not running")
        WILL_WORK=false
    fi

    if ! ss -uln 2>/dev/null | grep -q ":${PORT} "; then
        BLOCKERS+=("Nothing listening on UDP :$PORT")
        WILL_WORK=false
    fi
fi

if [[ "$WILL_WORK" == "true" ]]; then
    log_pass "All critical checks passed"
else
    log_critical "BLOCKERS FOUND:"
    for blocker in "${BLOCKERS[@]}"; do
        echo -e "           ${RED}• $blocker${NC}"
    done
fi

# ============================================
# SUMMARY
# ============================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    DIAGNOSTIC SUMMARY                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}PASSED:   $PASS${NC}"
echo -e "${YELLOW}WARNINGS: $WARN${NC}"
echo -e "${RED}FAILED:   $FAIL${NC}"
echo -e "${RED}CRITICAL: $CRITICAL${NC}"
echo ""

TOTAL_ISSUES=$((FAIL + CRITICAL))

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     CRITICAL ISSUES - CONNECTION WILL NOT WORK            ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Fix these issues first:"
    for blocker in "${BLOCKERS[@]}"; do
        echo -e "  ${RED}✗${NC} $blocker"
    done
    exit 2
elif [[ $FAIL -gt 0 ]]; then
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     ISSUES FOUND - MAY NOT WORK CORRECTLY                 ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "${YELLOW}Warnings present but should work${NC}"
    exit 0
else
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     ALL CHECKS PASSED - READY TO CONNECT                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 0
fi
