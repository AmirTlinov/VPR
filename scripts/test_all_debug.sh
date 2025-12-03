#!/usr/bin/env bash
set -euo pipefail

# Comprehensive test & debug sweep for VPR.
# Runs formatting, lint, full workspace tests with verbose output.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export RUST_BACKTRACE=1
export RUST_LOG=${RUST_LOG:-debug}

echo "==> fmt check"
cargo fmt --all -- --check

echo "==> clippy (all targets)"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> workspace tests (verbose)"
cargo test --workspace --all-targets -- --nocapture

echo "==> vpr-tui tests (extra nocapture)"
cargo test -p vpr-tui -- --nocapture

echo "==> vpr-app tests (extra nocapture)"
cargo test -p vpr-app -- --nocapture

echo "==> done: all debug tests passed"
