#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT="${EQUS_FIXTURE_BUNDLE:-$SCRIPT_DIR/../swift/Tests/EqusSdkTests/fixtures.generated.json}"

cd "$REPO_ROOT"
RUSTUP_TOOLCHAIN=1.97 cargo run -p equs-test-fixtures --all-features --bin fixture_gen -- --out "$OUT"
