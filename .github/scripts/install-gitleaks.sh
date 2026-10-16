#!/usr/bin/env bash
# Usage: install-gitleaks.sh  — prints the installed binary's path
set -euo pipefail

VERSION=8.30.1
SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

dest="${RUNNER_TEMP:-/tmp}"
tarball="$dest/gitleaks.tar.gz"

curl --proto '=https' --tlsv1.2 -sSfL -o "$tarball" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_x64.tar.gz"
echo "${SHA256}  ${tarball}" | sha256sum -c - >&2
tar -xzf "$tarball" -C "$dest" gitleaks
chmod +x "$dest/gitleaks"
rm -f "$tarball"
echo "$dest/gitleaks"
