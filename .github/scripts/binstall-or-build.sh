#!/usr/bin/env bash
# Usage: bash binstall-or-build.sh <crate> <verify-command>
set -euo pipefail

crate="${1:?crate name required}"
verify="${2:?verify command required}"

if cargo binstall -y "$crate" && eval "$verify" >/dev/null 2>&1; then
  exit 0
fi

echo "prebuilt for $crate unusable — building from source"
cargo install --force "$crate"
