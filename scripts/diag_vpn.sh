#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.." || exit 1

echo "=== VPR VPN diagnostics (repo: $(pwd)) ==="

fail() { echo "[FAIL] $1"; exit 1; }
warn() { echo "[WARN] $1"; }
ok() { echo "[ OK ] $1"; }

# 1) root check
if [ "$(id -u)" -ne 0 ]; then
  fail "Run as root: sudo $0"
fi

# 2) find vpn-client binary
BIN_CANDIDATES=(
  "${VPR_VPN_CLIENT:-}"
  "./target/release/vpn-client"
  "./target/release/vpn_client"
  "$(command -v vpn-client 2>/dev/null || true)"
  "$(command -v vpn_client 2>/dev/null || true)"
)
VPN_BIN=""
for c in "${BIN_CANDIDATES[@]}"; do
  if [ -n "${c}" ] && [ -x "${c}" ]; then VPN_BIN="${c}"; break; fi
done
[ -z "$VPN_BIN" ] && fail "vpn-client binary not found (set VPR_VPN_CLIENT or build release)"
ok "vpn-client found at $VPN_BIN"

# 3) interface present
if ip link show tun0 >/dev/null 2>&1; then
  ok "tun0 interface exists"
else
  fail "tun0 interface missing"
fi

# 4) address assigned
TUN_ADDR=$(ip -4 addr show dev tun0 | awk '/inet /{print $2}')
if [ -n "$TUN_ADDR" ]; then
  ok "tun0 has IPv4 $TUN_ADDR"
else
  warn "tun0 has no IPv4 address"
fi

# 5) default route via tun0
if ip route show default | grep -q "dev tun0"; then
  ok "default route goes via tun0"
else
  warn "default route is NOT via tun0"
fi

# 6) nftables kill-switch state
if nft list chain inet vpr_killswitch input >/dev/null 2>&1; then
  ok "nftables chain vpr_killswitch exists"
else
  warn "nftables chain vpr_killswitch missing"
fi

# 7) external IP check (compare main vs tun0)
curl_cmd="curl -s --max-time 5"
MAIN_IP=$($curl_cmd https://ifconfig.me 2>/dev/null || true)
TUN_IP=$($curl_cmd --interface tun0 https://ifconfig.me 2>/dev/null || true)

if [ -n "$MAIN_IP" ]; then ok "Main path IP: $MAIN_IP"; else warn "Cannot fetch IP on main route"; fi
if [ -n "$TUN_IP" ]; then ok "tun0 IP: $TUN_IP"; else warn "Cannot fetch IP via tun0"; fi

if [ -n "$MAIN_IP" ] && [ -n "$TUN_IP" ]; then
  if [ "$MAIN_IP" != "$TUN_IP" ]; then
    ok "Traffic appears to egress via tunnel (IPs differ)"
  else
    warn "External IP identical; tunnel may not route default traffic"
  fi
fi

echo "=== Diagnostics complete ==="
