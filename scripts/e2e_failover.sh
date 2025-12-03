#!/usr/bin/env bash
set -euo pipefail

# Multipath/failover e2e:
# - two outer links (veth) between client and server bridged on each side
# - vpn-server/client over TUN; continuous ping through tunnel to internet ns
# - drop one link; expect continuity (max outage <3s) and session alive

if [[ ${E2E_RERUN:-0} -eq 0 && $EUID -ne 0 ]]; then
  exec sudo -E E2E_RERUN=1 "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
LOG_DIR="${ROOT}/logs/e2e_failover"
mkdir -p "${LOG_DIR}"

RID=$(printf '%x' $$ | tail -c 6)
NS_S="vpf-${RID}-s"
NS_C="vpf-${RID}-c"
NS_I="vpf-${RID}-i"

S1="vps${RID}a"; C1="vpc${RID}a"
S2="vps${RID}b"; C2="vpc${RID}b"
SWAN="vps${RID}w"; IWAN="vpi${RID}"

BR_S="brs${RID}"
BR_C="brc${RID}"

OUTER_NET="10.240.0.0/24"
S_OUT="10.240.0.1"
C_OUT="10.240.0.2"

WAN_NET="198.19.0.0/24"
S_WAN="198.19.0.2"
I_WAN="198.19.0.1"

TUN_GW="10.9.0.1"
TUN_CLI="10.9.0.2"
MTU=1400

PIDS=()

log(){ echo "[e2e-failover] $*"; }

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  ip netns del "${NS_S}" 2>/dev/null || true
  ip netns del "${NS_C}" 2>/dev/null || true
  ip netns del "${NS_I}" 2>/dev/null || true
}
trap cleanup EXIT

require(){ for b in "$@"; do command -v "$b" >/dev/null 2>&1 || { echo "missing $b" >&2; exit 1; }; done; }
require ip ping

build_bins() {
  for f in vpn-server vpn-client; do
    [[ -x "${BIN}/${f}" ]] || { echo "missing ${f}, build first"; exit 1; }
  done
}

netns_setup() {
  ip netns add "${NS_S}"
  ip netns add "${NS_C}"
  ip netns add "${NS_I}"

  ip link add "${S1}" type veth peer name "${C1}"
  ip link add "${S2}" type veth peer name "${C2}"
  ip link add "${SWAN}" type veth peer name "${IWAN}"

  ip link set "${S1}" netns "${NS_S}"
  ip link set "${S2}" netns "${NS_S}"
  ip link set "${SWAN}" netns "${NS_S}"
  ip link set "${C1}" netns "${NS_C}"
  ip link set "${C2}" netns "${NS_C}"
  ip link set "${IWAN}" netns "${NS_I}"

  ip -n "${NS_S}" link add "${BR_S}" type bridge
  ip -n "${NS_C}" link add "${BR_C}" type bridge

  ip -n "${NS_S}" link set "${S1}" master "${BR_S}"
  ip -n "${NS_S}" link set "${S2}" master "${BR_S}"
  ip -n "${NS_C}" link set "${C1}" master "${BR_C}"
  ip -n "${NS_C}" link set "${C2}" master "${BR_C}"

  for ns in "${NS_S}" "${NS_C}" "${NS_I}"; do ip -n "$ns" link set lo up; done

  ip -n "${NS_S}" addr add "${S_OUT}/24" dev "${BR_S}"
  ip -n "${NS_C}" addr add "${C_OUT}/24" dev "${BR_C}"
  ip -n "${NS_S}" addr add "${S_WAN}/24" dev "${SWAN}"
  ip -n "${NS_I}" addr add "${I_WAN}/24" dev "${IWAN}"

  ip -n "${NS_S}" link set "${BR_S}" up
  ip -n "${NS_S}" link set "${S1}" up
  ip -n "${NS_S}" link set "${S2}" up
  ip -n "${NS_S}" link set "${SWAN}" up

  ip -n "${NS_C}" link set "${BR_C}" up
  ip -n "${NS_C}" link set "${C1}" up
  ip -n "${NS_C}" link set "${C2}" up

  ip -n "${NS_I}" link set "${IWAN}" up

  ip -n "${NS_S}" route add default via "${I_WAN}" dev "${SWAN}"
  ip netns exec "${NS_I}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  local IPT
  IPT=$(command -v iptables)
  ip netns exec "${NS_I}" "${IPT}" -t nat -A POSTROUTING -s "${TUN_GW}/24" -j MASQUERADE
}

start_inet() {
  ip netns exec "${NS_I}" python3 - <<'PY' &
import http.server, socketserver, os
PORT=8080
handler=http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("198.19.0.1", PORT), handler) as httpd:
    httpd.serve_forever()
PY
  PIDS+=($!)
}

start_vpn() {
  ip netns exec "${NS_S}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "${NS_S}" iptables -t nat -A POSTROUTING -s "10.9.0.0/24" -o "${SWAN}" -j MASQUERADE
  ip netns exec "${NS_S}" env RUST_LOG=warn "${BIN}/vpn-server" \
    --bind "${S_OUT}:4433" \
    --tun-name "tuns${RID}" \
    --tun-addr "${TUN_GW}" \
    --pool-start "${TUN_CLI}" --pool-end "10.9.0.50" \
    --mtu ${MTU} \
    --noise-dir "${ROOT}/secrets" --noise-name server \
    --cert "${ROOT}/secrets/server.crt" --key "${ROOT}/secrets/server.key" \
    --outbound-iface "${SWAN}" --enable-forwarding \
    >"${LOG_DIR}/vpn-server.log" 2>&1 &
  PIDS+=($!)

  ip netns exec "${NS_C}" env RUST_LOG=warn "${BIN}/vpn-client" \
    --server "${S_OUT}:4433" --server-name masque.local \
    --tun-name "tunc${RID}" --tun-addr "${TUN_CLI}" --gateway "${TUN_GW}" \
    --tun-netmask 255.255.255.0 --mtu ${MTU} --set-default-route \
    --noise-dir "${ROOT}/secrets" --noise-name client --server-pub "${ROOT}/secrets/server.noise.pub" \
    --insecure --idle-timeout 120 \
    >"${LOG_DIR}/vpn-client.log" 2>&1 &
  PIDS+=($!)
}

wait_tun() {
  for _ in {1..30}; do
    if ip -n "${NS_C}" link show "tunc${RID}" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  echo "tun not up" >&2; exit 1
}

run_ping_with_failover() {
  log "start ping through tunnel"
  ip netns exec "${NS_C}" ping -I "tunc${RID}" "${I_WAN}" -i 0.2 -w 12 > "${LOG_DIR}/ping.log" 2>&1 &
  PING_PID=$!
  sleep 3
  log "dropping link ${C1}"
  ip netns exec "${NS_C}" ip link set "${C1}" down
  sleep 4
  ip netns exec "${NS_C}" ip link set "${C1}" up
  wait $PING_PID || true

  local lost
  lost=$(awk '/transmitted/{print $4}' "${LOG_DIR}/ping.log")
  local transmitted
  transmitted=$(awk '/transmitted/{print $1}' "${LOG_DIR}/ping.log")
  local outage
  outage=$(awk '/time=/{print $7}' "${LOG_DIR}/ping.log" | wc -l)
  # Accept up to 3 lost packets (~0.6s) but we allow <3s => <=15 packets
  local lost_pkts=$(( transmitted - lost ))
  if (( lost_pkts > 15 )); then
    echo "failover outage too long: lost ${lost_pkts} pkts" >&2; exit 1; fi
  log "failover loss=${lost_pkts} packets (ok)"
}

main() {
  build_bins
  netns_setup
  start_inet
  start_vpn
  sleep 1
  wait_tun
  run_ping_with_failover
  log "failover e2e passed"
}

main "$@"
