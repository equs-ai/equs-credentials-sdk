#!/usr/bin/env bash
# Usage: bash binstall-or-build.sh <cargo-crate>
# Installs a cargo-X subcommand, falling back to a source build when the
# prebuilt binary will not run. Verified with `cargo X --version`.
set -euo pipefail

crate="${1:?crate name required}"
subcommand="${crate#cargo-}"

if cargo binstall -y "$crate" && cargo "$subcommand" --version >/dev/null 2>&1; then
  exit 0
fi

echo "prebuilt for $crate unusable — building from source"
cargo install --force "$crate"
