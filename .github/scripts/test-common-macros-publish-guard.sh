#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

manifest_version() {
  awk '/^\[package\]/{p=1;next} /^\[/{p=0} p&&/^version[[:space:]]*=/{gsub(/["[:space:]]/,"");sub(/^version=/,"");print;exit}' "$1"
}

guard() {
  local tag=$1 manifest=$2 version
  [[ "$tag" =~ ^common-macros/v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || return 1
  version=$(manifest_version "$manifest")
  [ "${BASH_REMATCH[1]}" = "$version" ] || return 1
}

fail=0
check() {
  local name=$1 expected=$2; shift 2
  if "$@"; then actual=0; else actual=1; fi
  [ "$actual" = "$expected" ] || { echo "FAIL: $name (expected $expected, got $actual)" >&2; fail=1; }
}

manifest=equs-common-macros/Cargo.toml
real=$(manifest_version "$manifest")
[ -n "$real" ] || { echo "FAIL: version not parsed from $manifest" >&2; exit 1; }

check "tag matches manifest" 0 guard "common-macros/v$real" "$manifest"
check "tag ahead of manifest" 1 guard common-macros/v99.99.99 "$manifest"
check "bare version tag rejected" 1 guard "$real" "$manifest"
check "sdk-style tag rejected" 1 guard 1.13.1 "$manifest"
check "prerelease tag rejected" 1 guard "common-macros/v$real-rc.1" "$manifest"
check "missing v rejected" 1 guard "common-macros/$real" "$manifest"
check "hyphen instead of slash rejected" 1 guard "common-macros-v$real" "$manifest"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '[package]\nname = "x"\nversion = "2.0.0"\n\n[dependencies]\nversion = "1.0.0"\n' > "$tmp/Cargo.toml"
check "version read from [package], not [dependencies]" 0 guard common-macros/v2.0.0 "$tmp/Cargo.toml"

[ "$fail" = 0 ] && echo "all common-macros publish-guard cases passed"
exit "$fail"
