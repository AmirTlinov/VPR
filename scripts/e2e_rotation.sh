#!/usr/bin/env bash
set -euo pipefail

# Rotation e2e:
# - bootstrap services in netns (reuse e2e_install)
# - baseline health-harness (DoH/ODoH) suspicion <0.35
# - rotate Noise key + TLS cert + ODoH seed, restart services
# - re-run health-harness and ensure suspicion <0.35
# - emit health.json with before/after; optional pcap if tcpdump exists

if [[ ${E2E_RERUN:-0} -eq 0 && $EUID -ne 0 ]]; then
  exec sudo -E E2E_RERUN=1 "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
LOG_DIR="${ROOT}/logs/e2e_rotation"
mkdir -p "${LOG_DIR}"

RID=$(printf '%x' $$ | tail -c 6)
NS_S="vpro-${RID}-s"
NS_C="vpro-${RID}-c"
VETH_S="vpror${RID}s"
VETH_C="vpror${RID}c"
SERVER_IP="10.220.0.1"
CLIENT_IP="10.220.0.2"
DOH_PORT=8053
MASQUE_PORT=4433
TMP_ROOT="$(mktemp -d /tmp/vpr-rot-XXXX)"
SERVER_ROOT="${TMP_ROOT}/server"
PIDS=()
STUB_PID=""
PCAP_PID=""

log(){ echo "[e2e-rotation] $*"; }

cleanup(){
  set +e
  if [[ -n "$PCAP_PID" ]]; then kill "$PCAP_PID" 2>/dev/null || true; fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  if [[ -n "$STUB_PID" ]]; then kill "$STUB_PID" 2>/dev/null || true; fi
  ip netns del "${NS_S}" 2>/dev/null || true
  ip netns del "${NS_C}" 2>/dev/null || true
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

require(){ for b in "$@"; do command -v "$b" >/dev/null 2>&1 || { echo "missing $b" >&2; exit 1; }; done; }
require ip python3

setup_netns(){
  ip netns add "${NS_S}"
  ip netns add "${NS_C}"
  ip link add "${VETH_S}" type veth peer name "${VETH_C}"
  ip link set "${VETH_S}" netns "${NS_S}"
  ip link set "${VETH_C}" netns "${NS_C}"
  ip -n "${NS_S}" addr add "${SERVER_IP}/24" dev "${VETH_S}"
  ip -n "${NS_C}" addr add "${CLIENT_IP}/24" dev "${VETH_C}"
  ip -n "${NS_S}" link set lo up
  ip -n "${NS_C}" link set lo up
  ip -n "${NS_S}" link set "${VETH_S}" up
  ip -n "${NS_C}" link set "${VETH_C}" up
}

start_dns_stub() {
  log "starting DNS stub inside ${NS_S}"
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
  STUB_PID=$!
}

install_stack(){
  log "install stack to ${SERVER_ROOT}"
  ip netns exec "${NS_S}" "${ROOT}/scripts/e2e_install.sh" \
    --prefix "${SERVER_ROOT}" \
    --bind-ip "${SERVER_IP}" \
    --doh-port "${DOH_PORT}" \
    --masque-port "${MASQUE_PORT}" \
    --upstream "127.0.0.1:1053"
}

start_services(){
  log "starting doh-gateway & masque-core"
  ip netns exec "${NS_S}" env RUST_LOG=warn "${BIN}/doh-gateway" \
    --config "${SERVER_ROOT}/etc/vpr/doh.toml" \
    >> "${LOG_DIR}/doh.log" 2>&1 &
  PIDS+=($!)
  ip netns exec "${NS_S}" env RUST_LOG=warn "${BIN}/masque-core" \
    --config "${SERVER_ROOT}/etc/vpr/masque.toml" \
    --noise-dir "${SERVER_ROOT}/secrets" --noise-name server \
    >> "${LOG_DIR}/masque.log" 2>&1 &
  PIDS+=($!)
  start_pcap
}

stop_services(){
  if [[ -n "$PCAP_PID" ]]; then kill "$PCAP_PID" 2>/dev/null || true; PCAP_PID=""; fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  PIDS=()
}

run_health(){
  local label="$1"
  local outfile="${LOG_DIR}/health-${label}.json"
  local out status=1 attempt=0
  set +e
  until [[ $attempt -ge 3 ]]; do
    out=$(ip netns exec "${NS_C}" env RUST_LOG=warn "${BIN}/health-harness" \
      --doh-url "http://${SERVER_IP}:${DOH_PORT}/dns-query" \
      --odoh-url "http://${SERVER_IP}:${DOH_PORT}/odoh-query" \
      --odoh-config-url "http://${SERVER_IP}:${DOH_PORT}/.well-known/odohconfigs" \
      --timeout-secs 5 --samples 1)
    status=$?
    [[ $status -eq 0 && "$out" == *"HEALTH_REPORT"* ]] && break
    attempt=$((attempt+1))
    sleep 1
  done
  set -e
  echo "$out" | tee "${LOG_DIR}/health-${label}.log" >/dev/null
  local report=$(echo "$out" | awk '/HEALTH_REPORT/{sub(/HEALTH_REPORT /,"",$0);print $0}' | tail -1)
  if [[ -z "$report" ]]; then echo "no HEALTH_REPORT" >&2; exit 1; fi
  echo "$report" > "$outfile"
  local susp
  susp=$(python3 - <<'PY' "$outfile"
import json, sys
path = sys.argv[1]
data = json.load(open(path))
print(data.get("suspicion", 1))
PY
)
  python3 - "$susp" <<'PY' || { echo "suspicion high $susp" >&2; exit 1; }
import sys
s=float(sys.argv[1])
sys.exit(0 if s < 0.35 else 1)
PY
  log "health ${label} suspicion=$susp ok"
  if [[ $status -ne 0 ]]; then echo "health-harness status $status" >&2; exit $status; fi
}

rotate(){
  log "rotating secrets (Noise/TLS/ODoH)"
  rm -rf "${SERVER_ROOT}/secrets"
  ip netns exec "${NS_S}" "${ROOT}/scripts/e2e_install.sh" \
    --prefix "${SERVER_ROOT}" \
    --bind-ip "${SERVER_IP}" \
    --doh-port "${DOH_PORT}" \
    --masque-port "${MASQUE_PORT}" \
    --upstream "127.0.0.1:1053"
}

write_summary(){
  local before after
  before=$(cat "${LOG_DIR}/health-before.json")
  after=$(cat "${LOG_DIR}/health-after.json")
  cat > "${LOG_DIR}/health.json" <<EOF
{"rotation":{"before":$before,"after":$after}}
EOF
  cat > "${LOG_DIR}/meta.json" <<EOF
{"labels":["e2e","smoke","rotation"],"pcap":"$(if [[ -f ${LOG_DIR}/rotation.pcap ]]; then echo "rotation.pcap"; else echo ""; fi)","logs":["doh.log","masque.log","health-before.log","health-after.log","health.json"],"ns_server":"${NS_S}","ns_client":"${NS_C}"}
EOF
  echo "e2e,smoke,rotation" > "${LOG_DIR}/labels.txt"
}

start_pcap(){
  if command -v tcpdump >/dev/null 2>&1; then
    log "starting pcap capture on ${NS_S}:${VETH_S}"
    ip netns exec "${NS_S}" tcpdump -i "${VETH_S}" -s 0 -w "${LOG_DIR}/rotation.pcap" \
      "port ${MASQUE_PORT} or port ${DOH_PORT}" >/dev/null 2>&1 &
    PCAP_PID=$!
  else
    log "tcpdump not found, skipping pcap capture"
  fi
}

main(){
  setup_netns
  start_dns_stub
  install_stack
  start_services
  sleep 2
  run_health "before"
  stop_services
  rotate
  start_services
  sleep 2
  run_health "after"
  write_summary
  log "rotation e2e passed"
}

main "$@"
