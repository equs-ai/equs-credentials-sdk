#!/usr/bin/env bash
# Usage: install-wasm-pack.sh — installs wasm-pack into CARGO_HOME/bin
set -euo pipefail

VERSION=0.15.0
SHA256=c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a
name="wasm-pack-v${VERSION}-x86_64-unknown-linux-musl"

dest="${CARGO_HOME:-$HOME/.cargo}/bin"
tmp="${RUNNER_TEMP:-/tmp}/${name}.tar.gz"

curl --proto '=https' --tlsv1.2 -sSfL -o "$tmp" \
  "https://github.com/rustwasm/wasm-pack/releases/download/v${VERSION}/${name}.tar.gz"
echo "${SHA256}  ${tmp}" | sha256sum -c - >&2

mkdir -p "$dest"
tar -xzf "$tmp" -C "$dest" --strip-components=1 "${name}/wasm-pack"
chmod +x "$dest/wasm-pack"
rm -f "$tmp"
