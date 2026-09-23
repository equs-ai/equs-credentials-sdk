#!/usr/bin/env bash
# Usage: install-binstall.sh — installs cargo-binstall into CARGO_HOME/bin
set -euo pipefail

VERSION=1.23.0

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset=cargo-binstall-x86_64-unknown-linux-gnu.tgz
    sha256=cdada45ad6bb501185ab309f5eef3f628b6bc44460746565cb3e0c7538815bf3 ;;
  Darwin-arm64)
    asset=cargo-binstall-aarch64-apple-darwin.zip
    sha256=0f679c0bc992c6b84fdcbb0f65492588447d26596ef387cb6cb1ba41ad8ceb33 ;;
  *)
    echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

dest="${CARGO_HOME:-$HOME/.cargo}/bin"
tmp="${RUNNER_TEMP:-/tmp}/$asset"

curl --proto '=https' --tlsv1.2 -sSfL -o "$tmp" \
  "https://github.com/cargo-bins/cargo-binstall/releases/download/v${VERSION}/${asset}"
if command -v sha256sum >/dev/null 2>&1; then
  echo "${sha256}  ${tmp}" | sha256sum -c - >&2
else
  echo "${sha256}  ${tmp}" | shasum -a 256 -c - >&2
fi

mkdir -p "$dest"
case "$asset" in
  *.tgz) tar -xzf "$tmp" -C "$dest" cargo-binstall ;;
  *.zip) unzip -qo "$tmp" cargo-binstall -d "$dest" ;;
esac
chmod +x "$dest/cargo-binstall"
rm -f "$tmp"
