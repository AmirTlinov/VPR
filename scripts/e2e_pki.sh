#!/usr/bin/env bash
set -euo pipefail

# PKI/bootstrap e2e:
# - generate root + intermediate CA
# - issue manifest signing key, sign manifest
# - happy path verify
# - negative cases: wrong signer pub, expired manifest, bad signature, corrupted JSON

if [[ ${E2E_RERUN:-0} -eq 0 && $EUID -ne 0 ]]; then
  exec sudo -E E2E_RERUN=1 "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/release"
TMP="$(mktemp -d /tmp/vpr-pki-XXXX)"
LOG_DIR="${ROOT}/logs/e2e_pki"
mkdir -p "${LOG_DIR}"

log(){ echo "[e2e-pki] $*"; }

cleanup() {
  rm -rf "${TMP}"
}
trap cleanup EXIT

require() { for b in "$@"; do command -v "$b" >/dev/null 2>&1 || { echo "missing $b" >&2; exit 1; }; done; }
require "${BIN}/vpr-keygen" "${BIN}/manifest-tool" python3

ROOT_DIR="${TMP}/root"
INT_DIR="${TMP}/int"
MANIFEST="${TMP}/manifest.json"
SIGNED_OK="${TMP}/manifest.signed.json"
SIGNED_BAD_SIG="${TMP}/manifest.bad_sig.json"
SIGNED_OLD="${TMP}/manifest.old.json"
SIGNED_WRONG="${TMP}/manifest.wrong_signer.json"

gen_manifest_payload() {
  local noise_hex
  noise_hex=$(python3 - <<'PY'
import os,binascii
print(binascii.hexlify(os.urandom(32)).decode())
PY
)
  cat >"$MANIFEST" <<EOF
{
  "version": 1,
  "created_at": $(date +%s),
  "expires_at": $(( $(date +%s) + 3600 )),
  "servers": [
    {
      "id": "srv1",
      "host": "1.1.1.1",
      "port": 443,
      "noise_pubkey": "${noise_hex}",
      "region": "us",
      "capabilities": ["masque","doh"],
      "weight": 100,
      "active": true
    }
  ],
  "comment": "test manifest",
  "odoh_relays": [],
  "front_domains": []
}
EOF
}

happy_path() {
  log "PKI root/intermediate"
  "${BIN}/vpr-keygen" init-root --output "${ROOT_DIR}" --org VPR >/dev/null
  "${BIN}/vpr-keygen" init-intermediate --root "${ROOT_DIR}" --output "${INT_DIR}" --name node1 >/dev/null

  log "Signing key"
  "${BIN}/vpr-keygen" gen-signing-key --output "${TMP}" --name manifest >/dev/null

  log "Manifest sign"
  "${BIN}/manifest-tool" sign --manifest "${MANIFEST}" --key-dir "${TMP}" --key-name manifest --out "${SIGNED_OK}"

  log "Manifest verify"
  "${BIN}/manifest-tool" verify --signed "${SIGNED_OK}" --pubkey "${TMP}/manifest.sign.pub" > "${LOG_DIR}/verify.log"
}

neg_bad_signature() {
  log "Negative: corrupted signature"
  SIGNED_OK="${SIGNED_OK}" SIGNED_BAD_SIG="${SIGNED_BAD_SIG}" python3 - <<'PY'
import json, os, sys
path = os.environ["SIGNED_OK"]
out = os.environ["SIGNED_BAD_SIG"]
data = json.load(open(path))
sig = list(bytes.fromhex(data["signature"]))
if not sig:
    sys.exit("empty signature")
sig[0] ^= 0xFF
data["signature"] = "".join(f"{b:02x}" for b in sig)
json.dump(data, open(out, "w"))
PY
  if "${BIN}/manifest-tool" verify --signed "${SIGNED_BAD_SIG}" --pubkey "${TMP}/manifest.sign.pub" 2> "${LOG_DIR}/neg_bad_sig.log"; then
    echo "expected failure for bad signature" >&2; exit 1; fi
}

neg_wrong_signer() {
  log "Negative: wrong signer pubkey"
  head -c 32 /dev/urandom > "${TMP}/wrong.pub"
  if "${BIN}/manifest-tool" verify --signed "${SIGNED_OK}" --pubkey "${TMP}/wrong.pub" 2> "${LOG_DIR}/neg_wrong_pub.log"; then
    echo "expected failure for wrong pubkey" >&2; exit 1; fi
}

neg_expired() {
  log "Negative: expired manifest"
  MANIFEST_PATH="${MANIFEST}" python3 - <<'PY'
import json, time, os
path=os.environ["MANIFEST_PATH"]; out=path + ".expired"
data=json.load(open(path))
data['expires_at']=int(time.time())-10
json.dump(data,open(out,"w"))
PY
  "${BIN}/manifest-tool" sign --manifest "${MANIFEST}.expired" --key-dir "${TMP}" --key-name manifest --out "${SIGNED_OLD}"
  if "${BIN}/manifest-tool" verify --signed "${SIGNED_OLD}" --pubkey "${TMP}/manifest.sign.pub" 2> "${LOG_DIR}/neg_expired.log"; then
    echo "expected failure for expired manifest" >&2; exit 1; fi
}

main() {
  gen_manifest_payload
  happy_path
  neg_bad_signature
  neg_wrong_signer
  neg_expired
  log "PKI/bootstrap e2e passed"
}

main "$@"
