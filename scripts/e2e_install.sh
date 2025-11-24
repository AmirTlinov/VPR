#!/usr/bin/env bash
set -euo pipefail

# Minimal installer used by e2e harness. It prepares secrets, configs,
# manifest and systemd unit copies in an isolated prefix (netns/VM).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=""
BIND_IP="10.200.0.1"
DOH_PORT=8053
MASQUE_PORT=4433
ODH_SEED_PATH=""
UPSTREAM="127.0.0.1:1053"

usage() {
  cat <<'EOF'
Usage: e2e_install.sh --prefix DIR [--bind-ip IP] [--doh-port N] [--masque-port N]
                      [--odoh-seed PATH] [--upstream HOST:PORT]

Creates self-contained /etc/vpr-style layout under DIR:
  secrets/ (Noise, TLS, ODoH seed)
  etc/vpr/{doh.toml,masque.toml}
  manifest.json (signed-later placeholder)
  systemd units with ExecStart pointing to workspace binaries
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --bind-ip) BIND_IP="$2"; shift 2 ;;
    --doh-port) DOH_PORT="$2"; shift 2 ;;
    --masque-port) MASQUE_PORT="$2"; shift 2 ;;
    --odoh-seed) ODH_SEED_PATH="$2"; shift 2 ;;
    --upstream) UPSTREAM="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${PREFIX}" ]]; then
  echo "--prefix is required" >&2
  exit 1
fi

BIN_DIR="${ROOT_DIR}/target/release"
SECRETS="${PREFIX}/secrets"
ETC_DIR="${PREFIX}/etc/vpr"
SYSTEMD_DIR="${PREFIX}/systemd"
mkdir -p "${SECRETS}" "${ETC_DIR}" "${SYSTEMD_DIR}" "${PREFIX}/logs"

log() { echo "[install] $*"; }

log "generating Noise keypair"
"${ROOT_DIR}/scripts/gen-noise-keys.sh" "${SECRETS}" >/dev/null

log "generating TLS cert for ${BIND_IP}"
CERT_PATH="${SECRETS}/server.crt"
KEY_PATH="${SECRETS}/server.key"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -subj "/CN=masque.local" \
  -addext "subjectAltName=IP:${BIND_IP},DNS:masque.local" \
  -keyout "${KEY_PATH}" -out "${CERT_PATH}" >/dev/null 2>&1

if [[ -z "${ODH_SEED_PATH}" ]]; then
  ODH_SEED_PATH="${SECRETS}/odoh_seed.bin"
fi
if [[ ! -f "${ODH_SEED_PATH}" ]]; then
  log "writing ODoH seed"
  head -c 32 /dev/urandom > "${ODH_SEED_PATH}"
fi

log "rendering configs"
cat >"${ETC_DIR}/doh.toml" <<EOF
bind = "${BIND_IP}:${DOH_PORT}"
upstream = "${UPSTREAM}"
doq_bind = "${BIND_IP}:8853"
odoh_enable = true
odoh_seed = "${ODH_SEED_PATH}"
EOF

cat >"${ETC_DIR}/masque.toml" <<EOF
bind = "${BIND_IP}:${MASQUE_PORT}"
quic_bind = "${BIND_IP}:9443"
h3_masque = "${BIND_IP}:8443"
cert = "${CERT_PATH}"
key = "${KEY_PATH}"
noise_dir = "${SECRETS}"
noise_name = "server"
EOF

log "templating systemd units"
sed "s|/usr/local/bin/masque-core|${BIN_DIR}/masque-core|; s|/etc/vpr/masque.toml|${ETC_DIR}/masque.toml|" \
  "${ROOT_DIR}/infra/systemd/vpr-masque.service" > "${SYSTEMD_DIR}/vpr-masque.service"
sed "s|/usr/local/bin/doh-gateway|${BIN_DIR}/doh-gateway|; s|/etc/vpr/doh.toml|${ETC_DIR}/doh.toml|" \
  "${ROOT_DIR}/infra/systemd/vpr-doh.service" > "${SYSTEMD_DIR}/vpr-doh.service"

log "writing manifest placeholder"
NOISE_PUB_B64=$(base64 <"${SECRETS}/server.noise.pub" | tr -d '\n')
cat >"${PREFIX}/manifest.json" <<EOF
{
  "version": 1,
  "generated_at": $(date +%s),
  "endpoints": {
    "doh": "http://${BIND_IP}:${DOH_PORT}/dns-query",
    "odoh": "http://${BIND_IP}:${DOH_PORT}/odoh-query",
    "odoh_configs": "http://${BIND_IP}:${DOH_PORT}/.well-known/odohconfigs",
    "masque": "${BIND_IP}:${MASQUE_PORT}"
  },
  "cert_path": "${CERT_PATH}",
  "noise_pub_b64": "${NOISE_PUB_B64}",
  "note": "unsigned test manifest for e2e harness"
}
EOF

log "done -> ${PREFIX}"
