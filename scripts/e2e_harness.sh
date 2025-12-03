#!/usr/bin/env bash
set -euo pipefail

# Deploy & connect acceptance harness:
# - creates isolated server/client netns with veth link
# - runs e2e_install.sh (cert+Noise+manifest+systemd templates)
# - starts doh-gateway + masque-core inside server netns
# - runs health-harness from client netns and asserts suspicion < 0.35

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
LOG_DIR="${ROOT}/logs/e2e"
mkdir -p "${LOG_DIR}"

if [[ ${E2E_RERUN:-0} -eq 0 && $EUID -ne 0 ]]; then
  exec sudo -E E2E_RERUN=1 "$0" "$@"
fi

RID=$(printf '%x' $$ | tail -c 6)
SERVER_NS="vpes-${RID}-s"
CLIENT_NS="vpes-${RID}-c"
VETH_SRV="ves${RID}"
VETH_CLI="vec${RID}"
SERVER_IP_CIDR="10.200.0.1/24"
CLIENT_IP_CIDR="10.200.0.2/24"
SERVER_IP="10.200.0.1"
DOH_PORT=8053
MASQUE_PORT=4433
TMP_ROOT="$(mktemp -d /tmp/vpr-e2e-XXXX)"
SERVER_ROOT="${TMP_ROOT}/server"
CLIENT_ROOT="${TMP_ROOT}/client"
DNS_STUB_PORT=1053

PIDS=()
SYSTEMD_UNITS=()

log() { echo "[e2e] $*"; }

cleanup() {
  set +e
  if command -v systemctl >/dev/null 2>&1 && [[ ${#SYSTEMD_UNITS[@]} -gt 0 ]]; then
    for u in "${SYSTEMD_UNITS[@]}"; do
      systemctl stop "$u" 2>/dev/null || true
      systemctl reset-failed "$u" 2>/dev/null || true
    done
  fi
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  ip netns del "${SERVER_NS}" 2>/dev/null || true
  ip netns del "${CLIENT_NS}" 2>/dev/null || true
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

require() {
  for bin in "$@"; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo "missing dependency: $bin" >&2
      exit 1
    fi
  done
}

require ip python3

build_binaries() {
  if [[ ! -x "${BIN}/masque-core" || ! -x "${BIN}/doh-gateway" || ! -x "${BIN}/health-harness" ]]; then
    log "building release binaries"
    cargo build --release -p masque-core -p doh-gateway -p health-harness -p vpr-crypto >/dev/null
  fi
}

setup_netns() {
  log "setting up namespaces"
  ip netns add "${SERVER_NS}"
  ip netns add "${CLIENT_NS}"
  ip link add "${VETH_SRV}" type veth peer name "${VETH_CLI}"
  ip link set "${VETH_SRV}" netns "${SERVER_NS}"
  ip link set "${VETH_CLI}" netns "${CLIENT_NS}"
  ip -n "${SERVER_NS}" addr add "${SERVER_IP_CIDR}" dev "${VETH_SRV}"
  ip -n "${CLIENT_NS}" addr add "${CLIENT_IP_CIDR}" dev "${VETH_CLI}"
  ip -n "${SERVER_NS}" link set lo up
  ip -n "${CLIENT_NS}" link set lo up
  ip -n "${SERVER_NS}" link set "${VETH_SRV}" up
  ip -n "${CLIENT_NS}" link set "${VETH_CLI}" up
  ip -n "${CLIENT_NS}" route add "${SERVER_IP}/32" dev "${VETH_CLI}"
}

start_dns_stub() {
  log "starting UDP DNS stub inside ${SERVER_NS}"
  ip netns exec "${SERVER_NS}" python3 - <<'PY' &
import socket, struct, sys
bind_addr = ('127.0.0.1', 1053)
resp_ip = '10.0.0.1'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(bind_addr)
def build_response(data):
    if len(data) < 12:
        return b''
    tid = data[:2]
    flags = b"\x81\x80"
    qdcount = data[4:6]
    ancount = qdcount
    header = tid + flags + qdcount + ancount + b"\x00\x00\x00\x00"
    # question ends at first zero byte after offset 12
    end = data.find(b"\x00", 12)
    if end == -1:
        return b''
    question = data[12:end+5]  # include null + qtype+qclass
    answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04" + socket.inet_aton(resp_ip)
    return header + question + answer
try:
    while True:
        pkt, addr = s.recvfrom(2048)
        resp = build_response(pkt)
        if resp:
            s.sendto(resp, addr)
except KeyboardInterrupt:
    pass
PY
  PIDS+=($!)
}

run_install() {
  log "running installer into ${SERVER_ROOT}"
  ip netns exec "${SERVER_NS}" "${ROOT}/scripts/e2e_install.sh" \
    --prefix "${SERVER_ROOT}" \
    --bind-ip "${SERVER_IP}" \
    --doh-port "${DOH_PORT}" \
    --masque-port "${MASQUE_PORT}" \
    --upstream "127.0.0.1:${DNS_STUB_PORT}"
}

start_service() {
  local unit="$1"; shift
  local log_file="$1"; shift
  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run --unit "${unit}" --quiet --collect \
      --property=StandardOutput=append:"${log_file}" \
      --property=StandardError=append:"${log_file}" "$@"
    SYSTEMD_UNITS+=("${unit}")
  else
    "$@" >"${log_file}" 2>&1 &
    PIDS+=($!)
  fi
}

start_services() {
  log "starting doh-gateway"
  start_service "vpr-e2e-doh" "${LOG_DIR}/doh.log" \
    ip netns exec "${SERVER_NS}" env RUST_LOG=info "${BIN}/doh-gateway" \
      --config "${SERVER_ROOT}/etc/vpr/doh.toml"

  log "starting masque-core"
  start_service "vpr-e2e-masque" "${LOG_DIR}/masque.log" \
    ip netns exec "${SERVER_NS}" env RUST_LOG=info "${BIN}/masque-core" \
      --config "${SERVER_ROOT}/etc/vpr/masque.toml" \
      --noise-dir "${SERVER_ROOT}/secrets" --noise-name server
}

run_health() {
  log "running health-harness from ${CLIENT_NS}"
  local health_log="${LOG_DIR}/health-$(date +%s).log"
  set +e
  HEALTH_OUTPUT=$(ip netns exec "${CLIENT_NS}" env RUST_LOG=warn "${BIN}/health-harness" \
    --doh-url "http://${SERVER_IP}:${DOH_PORT}/dns-query" \
    --odoh-url "http://${SERVER_IP}:${DOH_PORT}/odoh-query" \
    --odoh-config-url "http://${SERVER_IP}:${DOH_PORT}/.well-known/odohconfigs" \
    --timeout-secs 5 --samples 2)
  local status=$?
  set -e
  echo "$HEALTH_OUTPUT" | tee "${health_log}" >/dev/null
  local report=$(echo "$HEALTH_OUTPUT" | awk '/HEALTH_REPORT/{sub(/HEALTH_REPORT /,"",$0);print $0}' | tail -1)
  if [[ -z "$report" ]]; then
    echo "HEALTH_REPORT not found" >&2
    exit 1
  fi
  local suspicion
  suspicion=$(python3 - "$report" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
print(data.get("suspicion", 1))
PY
)
  if python3 - "$suspicion" <<'PY'
import sys
susp=float(sys.argv[1])
sys.exit(0 if susp < 0.35 else 1)
PY
  then
    log "suspicion=${suspicion} OK"
  else
    echo "suspicion ${suspicion} is too high" >&2
    exit 1
  fi
  echo "$report" > "${LOG_DIR}/health.json"
  if [[ $status -ne 0 ]]; then
    echo "health-harness exited with $status" >&2
    exit $status
  fi
}

main() {
  build_binaries
  setup_netns
  start_dns_stub
  run_install
  start_services
  sleep 2
  run_health
  log "deploy&connect harness passed"
}

main "$@"
