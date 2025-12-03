#!/bin/bash
set -e
pkill -9 vpn-client 2>/dev/null || true
sleep 2
RUST_LOG=info timeout 45 ./target/release/vpn-client \
  --server 64.176.70.203:4433 \
  --server-name vultr \
  --tun-name vpr0 \
  --noise-dir secrets \
  --noise-name client \
  --server-pub secrets/server.noise.pub \
  --insecure
