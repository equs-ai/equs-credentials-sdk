#!/usr/bin/env bash
# Executable form of the binstall_or_build helper defined inline in the
# .rust_tooling_script anchor of .gitlab-ci.yml (lines 38-44, the
# binstall_or_build function body at 42-44). GitHub Actions runs each `run:`
# block in a fresh shell, so a sourced function would not survive between
# steps.
#
# Usage: binstall-or-build.sh <crate> <verify-command>
set -euo pipefail

crate="${1:?crate name required}"
verify="${2:?verify command required}"

if cargo binstall -y "$crate" && eval "$verify" >/dev/null 2>&1; then
  exit 0
fi

echo "prebuilt for $crate unusable — building from source"
cargo install --force "$crate"
