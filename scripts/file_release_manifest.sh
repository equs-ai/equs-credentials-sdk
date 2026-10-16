#!/usr/bin/env bash
# Renders the release manifest for a release shipped as plain files. The digest
# is the sha256 of each file the publish job attached — no registry calls, so the
# manifest depends on nothing but the release's files.
set -euo pipefail

USAGE="usage: file_release_manifest.sh <component> <output> <file>..."
COMPONENT="${1:?$USAGE}"
OUT="${2:?$USAGE}"
shift 2
[ "$#" -gt 0 ] || { echo "$USAGE" >&2; exit 1; }

: "${CI_COMMIT_TAG:?}"
: "${CI_COMMIT_SHA:?}"

# Wrapper tags carry a prefix, so the release version is passed in.
RELEASE_VERSION="${RELEASE_VERSION:-$CI_COMMIT_TAG}"

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

repo_path() {
  local url
  url=$(sed -n 's/^repository = "\(.*\)"$/\1/p' Cargo.toml | head -1)
  printf '%s' "${url#https://github.com/}"
}

artifact() {
  local name
  name=$(basename "$1")
  if [ ! -f "$1" ]; then
    echo "warning: no file $1" >&2
    printf '      - name: "%s"\n        version: "%s"\n        digest: null\n' "$name" "$RELEASE_VERSION"
    return
  fi

  printf '      - name: "%s"\n        version: "%s"\n        digest: "sha256:%s"\n' \
    "$name" "$RELEASE_VERSION" "$(sha256 "$1")"
}

{
  printf 'release: "%s"\n' "$RELEASE_VERSION"
  printf 'generated_at: "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'components:\n'
  printf '  "%s":\n' "$COMPONENT"
  printf '    repo: "%s"\n' "$(repo_path)"
  printf '    commit: "%s"\n' "$CI_COMMIT_SHA"
  printf '    tag: "%s"\n' "$CI_COMMIT_TAG"
  printf '    artifacts:\n'
  for f in "$@"; do
    artifact "$f"
  done
} >"$OUT"

echo "wrote ${OUT}" >&2
