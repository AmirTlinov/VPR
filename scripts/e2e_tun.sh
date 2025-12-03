#!/usr/bin/env bash
set -euo pipefail

# TUN/TAP end-to-end test:
# - builds and starts vpn-server and vpn-client in isolated netns
# - configures MTU, routing, NAT, DNS
# - runs ping, HTTP, and iperf-like throughput via tunnel
# - enforces iptables leak check on outer interface (no clear traffic outside tunnel)

if [[ ${E2E_RERUN:-0} -eq 0 && $EUID -ne 0 ]]; then
  exec sudo -E E2E_RERUN=1 "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
TMP="$(mktemp -d /tmp/vpr-tun-XXXX)"
LOG_DIR="${ROOT}/logs/e2e_tun"
mkdir -p "${LOG_DIR}"

RID=$(printf '%x' $$ | tail -c 6)
NS_S="vpts-${RID}-s"
NS_C="vpts-${RID}-c"
NS_I="vpts-${RID}-i"
VETH_SC="vps${RID}"
VETH_CS="vpc${RID}"
VETH_SI="vwi${RID}"
VETH_IS="vii${RID}"
TUN_S="tuns${RID}"
TUN_C="tunc${RID}"

OUTER_SRV="10.201.0.1"
OUTER_CLI="10.201.0.2"
WAN_SRV="198.18.0.2"
WAN_INET="198.18.0.1"

TUN_GW="10.9.0.1"
TUN_CLI="10.9.0.2"
TUN_CIDR="10.9.0.0/24"
MTU=1400

HTTP_PORT=8080
PERF_PORT=5201

PIDS=()

log() { echo "[e2e-tun] $*"; }

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  ip netns del "${NS_S}" 2>/dev/null || true
  ip netns del "${NS_C}" 2>/dev/null || true
  ip netns del "${NS_I}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

require() {
  for b in "$@"; do
    if ! command -v "$b" >/dev/null 2>&1; then
      echo "missing dependency: $b" >&2
      exit 1
    fi
  done
}

require ip iptables python3 curl cargo

build_bins() {
  if [[ ! -x "${BIN}/vpn-server" || ! -x "${BIN}/vpn-client" ]]; then
    log "building vpn-server/vpn-client"
    cargo build --release -p masque-core >/dev/null
  fi
}

gen_material() {
  mkdir -p "${TMP}/keys"
  "${ROOT}/scripts/gen-noise-keys.sh" "${TMP}/keys" >/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
    -subj "/CN=masque.local" \
    -addext "subjectAltName=IP:${OUTER_SRV},DNS:masque.local" \
    -keyout "${TMP}/server.key" -out "${TMP}/server.crt" >/dev/null 2>&1
}

netns_base() {
  log "creating namespaces"
  ip netns add "${NS_S}"
  ip netns add "${NS_C}"
  ip netns add "${NS_I}"

  ip link add "${VETH_SC}" type veth peer name "${VETH_CS}"
  ip link add "${VETH_SI}" type veth peer name "${VETH_IS}"

  ip link set "${VETH_SC}" netns "${NS_S}"
  ip link set "${VETH_CS}" netns "${NS_C}"
  ip link set "${VETH_SI}" netns "${NS_S}"
  ip link set "${VETH_IS}" netns "${NS_I}"

  ip -n "${NS_S}" addr add "${OUTER_SRV}/24" dev "${VETH_SC}"
  ip -n "${NS_C}" addr add "${OUTER_CLI}/24" dev "${VETH_CS}"
  ip -n "${NS_S}" addr add "${WAN_SRV}/24" dev "${VETH_SI}"
  ip -n "${NS_I}" addr add "${WAN_INET}/24" dev "${VETH_IS}"

  ip -n "${NS_S}" link set lo up
  ip -n "${NS_C}" link set lo up
  ip -n "${NS_I}" link set lo up
  ip -n "${NS_S}" link set "${VETH_SC}" up
  ip -n "${NS_C}" link set "${VETH_CS}" up
  ip -n "${NS_S}" link set "${VETH_SI}" up
  ip -n "${NS_I}" link set "${VETH_IS}" up

  ip -n "${NS_S}" route add default via "${WAN_INET}"
  ip -n "${NS_C}" route add "${OUTER_SRV}/32" dev "${VETH_CS}"
}

start_inet_services() {
  log "starting HTTP/perf services in ${NS_I}"
  ip netns exec "${NS_I}" python3 -m http.server "${HTTP_PORT}" --bind "${WAN_INET}" >/dev/null 2>&1 &
  PIDS+=($!)
  ip netns exec "${NS_I}" python3 - <<'PY' &
import os, socket, time
BIND=("198.18.0.1", 5201)
srv=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(BIND)
srv.listen(5)
while True:
    conn, _ = srv.accept()
    data = os.urandom(65535)
    end = time.time() + 5
    sent = 0
    try:
        while time.time() < end:
            conn.sendall(data)
            sent += len(data)
    finally:
        conn.close()
PY
  PIDS+=($!)
}

start_server() {
  log "starting vpn-server"
  ip netns exec "${NS_S}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "${NS_S}" iptables -t nat -A POSTROUTING -s "${TUN_CIDR}" -o "${VETH_SI}" -j MASQUERADE
  ip netns exec "${NS_S}" env RUST_LOG=info "${BIN}/vpn-server" \
    --bind "${OUTER_SRV}:4433" \
    --tun-name "${TUN_S}" \
    --tun-addr "${TUN_GW}" \
    --pool-start "${TUN_CLI}" \
    --pool-end "10.9.0.50" \
    --mtu ${MTU} \
    --noise-dir "${TMP}/keys" --noise-name server \
    --cert "${TMP}/server.crt" --key "${TMP}/server.key" \
    --outbound-iface "${VETH_SI}" --enable-forwarding \
    --idle-timeout 120 \
    >"${LOG_DIR}/vpn-server.log" 2>&1 &
  PIDS+=($!)
}

start_client() {
  log "starting vpn-client"
  ip netns exec "${NS_C}" env RUST_LOG=info "${BIN}/vpn-client" \
    --server "${OUTER_SRV}:4433" --server-name masque.local \
    --tun-name "${TUN_C}" --tun-addr "${TUN_CLI}" --gateway "${TUN_GW}" \
    --tun-netmask 255.255.255.0 --mtu ${MTU} --set-default-route \
    --noise-dir "${TMP}/keys" --noise-name client --server-pub "${TMP}/keys/server.noise.pub" \
    --insecure --idle-timeout 60 \
    >"${LOG_DIR}/vpn-client.log" 2>&1 &
  PIDS+=($!)
}

wait_tun() {
  log "waiting for tunnel"
  for _ in {1..30}; do
    if ip -n "${NS_C}" link show "${TUN_C}" >/dev/null 2>&1; then
      ip -n "${NS_C}" addr show "${TUN_C}"
      return 0
    fi
    sleep 0.3
  done
  echo "TUN device not created" >&2
  exit 1
}

setup_leak_guard() {
  log "installing leak guard iptables"
  ip netns exec "${NS_C}" iptables -N VPRLEAK || true
  ip netns exec "${NS_C}" iptables -F VPRLEAK
  ip netns exec "${NS_C}" iptables -A VPRLEAK -j DROP
  ip netns exec "${NS_C}" iptables -I OUTPUT 1 -o "${VETH_CS}" ! -d "${OUTER_SRV}" -j VPRLEAK
}

run_ping() {
  log "ping gateway"
  ip netns exec "${NS_C}" ping -c 2 -W 1 "${TUN_GW}" >/dev/null
  log "ping internet host"
  ip netns exec "${NS_C}" ping -c 2 -W 1 "${WAN_INET}" >/dev/null
}

run_http() {
  log "HTTP over tunnel"
  ip netns exec "${NS_C}" curl -s --max-time 5 "http://${WAN_INET}:${HTTP_PORT}/" >/dev/null
}

run_perf() {
  log "iperf-like throughput"
  local bytes
  bytes=$(ip netns exec "${NS_C}" python3 - "$WAN_INET" "$PERF_PORT" <<'PY'
import socket, sys, time
host=sys.argv[1]; port=int(sys.argv[2])
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))
deadline=time.time()+5
total=0
while time.time()<deadline:
    try:
        data=s.recv(65535)
    except ConnectionResetError:
        break
    if not data:
        break
    total+=len(data)
s.close()
print(total)
PY
)
  if [[ -z "$bytes" || "$bytes" -lt 1000000 ]]; then
    echo "throughput too low: ${bytes}" >&2
    exit 1
  fi
  log "throughput bytes=${bytes} (~$((bytes*8/5/1000000)) Mbps)"
}

check_leak() {
  set +u
  local pkt
  pkt=$(ip netns exec "${NS_C}" iptables -vnL VPRLEAK 2>/dev/null | awk 'NR==2{print $1}') || pkt=0
  pkt=${pkt:-0}
  if [[ "$pkt" -ne 0 ]]; then
    echo "Leak detected: $pkt packets on outer interface" >&2
    exit 1
  fi
  log "leak check passed"
  set -u
}

main() {
  build_bins
  gen_material
  netns_base
  start_inet_services
  start_server
  sleep 1
  start_client
  wait_tun
  setup_leak_guard
  run_ping
  run_http
  run_perf
  check_leak
  log "TUN/TAP e2e passed"
}

main "$@"
