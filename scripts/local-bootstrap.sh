#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BIN="${ROOT}/target/release"

mkdir -p "${ROOT}/secrets" "${ROOT}/logs"

# Noise keys (IK) - now expects server.noise.key/pub
if [[ ! -f "${ROOT}/secrets/server.noise.key" ]]; then
  "${ROOT}/scripts/gen-noise-keys.sh" "${ROOT}/secrets"
fi

# Generate self-signed cert/key for TLS
CRT="${ROOT}/secrets/server.crt"
KEY="${ROOT}/secrets/server.key"
if [[ ! -f "${CRT}" || ! -f "${KEY}" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=localhost" \
    -keyout "${KEY}" -out "${CRT}"
fi

# Generate ODoH seed once
SEED="${ROOT}/secrets/odoh_seed.bin"
if [[ ! -f "${SEED}" ]]; then
  head -c 32 /dev/urandom > "${SEED}"
fi

export RUST_LOG=info

echo "[+] starting doh-gateway on :8053 (DoQ on :8853)"
"${BIN}/doh-gateway" \
  --bind 0.0.0.0:8053 \
  --doq-bind 0.0.0.0:8853 \
  --odoh-enable \
  --odoh-seed "${SEED}" \
  >"${ROOT}/logs/doh-gateway.log" 2>&1 &
DOH_PID=$!

echo "[+] starting masque-core on :4433"
"${BIN}/masque-core" \
  --bind 0.0.0.0:4433 \
  --cert "${CRT}" \
  --key "${KEY}" \
  --noise-dir "${ROOT}/secrets" \
  --noise-name server \
  >"${ROOT}/logs/masque-core.log" 2>&1 &
MASQUE_PID=$!

sleep 3

echo "[+] running health-harness"
"${BIN}/health-harness" \
  --doh-url http://127.0.0.1:8053/dns-query \
  --odoh-url http://127.0.0.1:8053/odoh-query \
  --odoh-config-url http://127.0.0.1:8053/.well-known/odohconfigs \
  --samples 3

echo "[+] stopping services"
kill ${DOH_PID} ${MASQUE_PID} 2>/dev/null || true
