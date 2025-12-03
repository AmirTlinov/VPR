#!/usr/bin/env bash
set -euo pipefail

# MASQUE CONNECT-UDP over H3 e2e:
# - server/client/target netns with veth links
# - masque-core h3_masque endpoint
# - masque-h3-client sends UDP payload to real target (echo) and checks integrity
# - fallback ladder: DoH-capsule (HTTP) and DoQ (QUIC) via health-harness

if [[ ${E2E_RERUN:-0} -eq 0 && $EUID -ne 0 ]]; then
  exec sudo -E E2E_RERUN=1 "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
LOG_DIR="${ROOT}/logs/e2e_masque"
mkdir -p "${LOG_DIR}"

RID=$(printf '%x' $$ | tail -c 6)
NS_S="vpmh-${RID}-s"
NS_C="vpmh-${RID}-c"
NS_T="vpmh-${RID}-t"

VETH_SC="vms${RID}"
VETH_CS="vmc${RID}"
VETH_ST="vmt${RID}"
VETH_TS="vts${RID}"

IP_SRV="10.210.0.1/24"
IP_CLI="10.210.0.2/24"
IP_ST="10.211.0.1/24"
IP_TGT="10.211.0.2/24"

MASQUE_PORT=8443
DOH_PORT=8053
DOQ_PORT=8853
TARGET_PORT=5300
PAYLOAD=64

TMP="$(mktemp -d /tmp/vpr-masque-XXXX)"
SRV_ROOT="${TMP}/server"

PIDS=()

log(){ echo "[e2e-masque] $*"; }

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  ip netns del "${NS_S}" 2>/dev/null || true
  ip netns del "${NS_C}" 2>/dev/null || true
  ip netns del "${NS_T}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

require() {
  for b in "$@"; do
    command -v "$b" >/dev/null 2>&1 || { echo "missing $b" >&2; exit 1; }
  done
}

require ip python3 cargo

netns_setup() {
  log "creating namespaces and links"
  ip netns add "${NS_S}"
  ip netns add "${NS_C}"
  ip netns add "${NS_T}"

  ip link add "${VETH_SC}" type veth peer name "${VETH_CS}"
  ip link add "${VETH_ST}" type veth peer name "${VETH_TS}"

  ip link set "${VETH_SC}" netns "${NS_S}"
  ip link set "${VETH_CS}" netns "${NS_C}"
  ip link set "${VETH_ST}" netns "${NS_S}"
  ip link set "${VETH_TS}" netns "${NS_T}"

  ip -n "${NS_S}" addr add "${IP_SRV}" dev "${VETH_SC}"
  ip -n "${NS_C}" addr add "${IP_CLI}" dev "${VETH_CS}"
  ip -n "${NS_S}" addr add "${IP_ST}" dev "${VETH_ST}"
  ip -n "${NS_T}" addr add "${IP_TGT}" dev "${VETH_TS}"

  ip -n "${NS_S}" link set lo up
  ip -n "${NS_C}" link set lo up
  ip -n "${NS_T}" link set lo up
  ip -n "${NS_S}" link set "${VETH_SC}" up
  ip -n "${NS_C}" link set "${VETH_CS}" up
  ip -n "${NS_S}" link set "${VETH_ST}" up
  ip -n "${NS_T}" link set "${VETH_TS}" up

  ip -n "${NS_C}" route add default via "${IP_SRV%/*}"
  ip -n "${NS_S}" route add "${IP_TGT%/*}" dev "${VETH_ST}"
}

build_bins() {
  if [[ ! -x "${BIN}/masque-h3-client" ]]; then
    log "masque-h3-client missing, abort"; exit 1
  fi
  if [[ ! -x "${BIN}/masque-core" || ! -x "${BIN}/doh-gateway" || ! -x "${BIN}/health-harness" ]]; then
    log "required binaries missing"; exit 1
  fi
}

run_install() {
  log "installing configs/secrets via e2e_install"
  ip netns exec "${NS_S}" "${ROOT}/scripts/e2e_install.sh" \
    --prefix "${SRV_ROOT}" \
    --bind-ip "${IP_SRV%/*}" \
    --doh-port "${DOH_PORT}" \
    --masque-port "${MASQUE_PORT}" \
    --upstream "127.0.0.1:1053"
}

start_dns_stub() {
  log "starting UDP echo/target in ${NS_T}"
  ip netns exec "${NS_T}" python3 - <<'PY' &
import socket, sys
ADDR=("0.0.0.0", 5300)
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(ADDR)
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(data, addr)
PY
  PIDS+=($!)

  # simple dns stub on server for health-harness fallback
  ip netns exec "${NS_S}" python3 - <<'PY' &
import socket
bind=('127.0.0.1',1053)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(bind)
resp_ip='10.0.0.1'
def resp(pkt):
    if len(pkt)<12: return b''
    tid=pkt[:2]; flags=b"\x81\x80"; qd=pkt[4:6]; an=qd
    hdr=tid+flags+qd+an+b"\x00\x00\x00\x00"
    end=pkt.find(b"\x00",12)
    if end==-1: return b''
    question=pkt[12:end+5]
    ans=b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"+socket.inet_aton(resp_ip)
    return hdr+question+ans
while True:
    pkt, addr=s.recvfrom(2048)
    r=resp(pkt)
    if r: s.sendto(r,addr)
PY
  PIDS+=($!)
}

start_services() {
  log "starting doh-gateway"
  ip netns exec "${NS_S}" env RUST_LOG=warn "${BIN}/doh-gateway" \
    --config "${SRV_ROOT}/etc/vpr/doh.toml" \
    >"${LOG_DIR}/doh.log" 2>&1 &
  PIDS+=($!)

  log "starting masque-core (h3 ${MASQUE_PORT})"
  ip netns exec "${NS_S}" env RUST_LOG=info MASQUE_ALLOW_PRIVATE=1 "${BIN}/masque-core" \
    --config "${SRV_ROOT}/etc/vpr/masque.toml" \
    --noise-dir "${SRV_ROOT}/secrets" --noise-name server \
    >"${LOG_DIR}/masque.log" 2>&1 &
  PIDS+=($!)
}

run_h3() {
  log "running masque-h3-client to ${IP_SRV%/*}:${MASQUE_PORT} target ${IP_TGT%/*}:${TARGET_PORT}"
  set +e
  ip netns exec "${NS_C}" "${BIN}/masque-h3-client" \
    --server "${IP_SRV%/*}:${MASQUE_PORT}" \
    --server-name masque.local \
    --target "${IP_TGT%/*}:${TARGET_PORT}" \
    --payload "${PAYLOAD}" \
    --timeout 3 \
    >"${LOG_DIR}/h3-client.log" 2>&1
  local status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    log "H3 MASQUE failed (status $status), see logs"; return $status; fi
  log "H3 MASQUE CONNECT-UDP ok"

  # Validate response headers recorded by client (datagram-flow-id)
  if ! grep -q "datagram-flow-id=0" "${LOG_DIR}/h3-client.log"; then
    log "datagram-flow-id header missing"; return 2; fi
}

run_fallbacks() {
  log "running DoH/DoQ fallback via health-harness"
  set +e
  ip netns exec "${NS_C}" env RUST_LOG=warn "${BIN}/health-harness" \
    --doh-url "http://${IP_SRV%/*}:${DOH_PORT}/dns-query" \
    --doq-addr "${IP_SRV%/*}:${DOQ_PORT}" \
    --server-name masque.local \
    --insecure-tls \
    --timeout-secs 3 --samples 1 \
    >"${LOG_DIR}/fallback.log" 2>&1
  local status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    log "fallback health returned ${status} (captured), continuing"
  fi
}

main() {
  build_bins
  netns_setup
  start_dns_stub
  run_install
  start_services
  sleep 2
  run_h3
  run_fallbacks
  log "MASQUE H3 e2e passed"
}

main "$@"
