#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BIN="${ROOT}/target/debug"

mkdir -p "${ROOT}/secrets" "${ROOT}/logs"

# Noise keys (IK)
if [[ ! -f "${ROOT}/secrets/server.key" ]]; then
  "${ROOT}/scripts/gen-noise-keys.sh" "${ROOT}/secrets"
fi

# Generate cert/key for DoQ if absent
CRT="${ROOT}/secrets/doq.crt"
KEY="${ROOT}/secrets/doq.key"
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

echo "[+] starting doh-gateway"
"${BIN}/doh-gateway" \
  --config "${ROOT}/config/doh.toml.sample" \
  --odoh-enable \
  --odoh-seed "${SEED}" \
  --doq-cert "${CRT}" \
  --doq-key "${KEY}" \
  >"${ROOT}/logs/doh-gateway.log" 2>&1 &
DOH_PID=$!

echo "[+] starting masque-core"
"${BIN}/masque-core" --config "${ROOT}/config/masque.toml.sample" --noise-key "${ROOT}/secrets/server.key" \
  >"${ROOT}/logs/masque-core.log" 2>&1 &
MASQUE_PID=$!

sleep 2

echo "[+] running health-harness"
"${BIN}/health-harness" \
  --doh-url http://127.0.0.1:8053/dns-query \
  --doq-addr 127.0.0.1:8853 \
  --odoh-url http://127.0.0.1:8053/odoh-query \
  --odoh-config-url http://127.0.0.1:8053/.well-known/odohconfigs \
  --insecure-tls \
  --samples 3

echo "[+] stopping services"
kill ${DOH_PID} ${MASQUE_PID}
