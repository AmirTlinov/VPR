#!/usr/bin/env bash
set -euo pipefail

OUT=${1:-secrets}
mkdir -p "$OUT"

gen_pair() {
  local name="$1"
  local sk="$OUT/${name}.noise.key"
  local pk="$OUT/${name}.noise.pub"
  head -c 32 /dev/urandom > "$sk"
  # derive pub via curve25519 basepoint mult using python
  python - <<'PY' "$sk" "$pk"
import sys, nacl.bindings
sk_path, pk_path = sys.argv[1:3]
sk = open(sk_path, 'rb').read()
pk = nacl.bindings.crypto_scalarmult_base(sk)
open(pk_path, 'wb').write(pk)
PY
  echo "generated $sk and $pk"
}

gen_pair server
gen_pair client
