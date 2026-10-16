#!/usr/bin/env bash
# Renders the release manifest for one Maven release. The digest is the sha256
# of the AAR the publish job signed and uploaded — no registry calls, so the
# manifest depends on nothing but the release's files.
set -euo pipefail

COORDINATE="${1:?usage: maven_release_manifest.sh <group:artifact> <output> <file>}"
OUT="${2:?usage: maven_release_manifest.sh <group:artifact> <output> <file>}"
FILE="${3:?usage: maven_release_manifest.sh <group:artifact> <output> <file>}"

: "${CI_COMMIT_TAG:?}"
: "${CI_COMMIT_SHA:?}"

# Maven tags carry a prefix, so the release version is passed in.
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
  if [ ! -f "$FILE" ]; then
    echo "warning: no file ${FILE} for ${COORDINATE}" >&2
    printf '      - name: "%s"\n        version: "%s"\n        digest: null\n' "$COORDINATE" "$RELEASE_VERSION"
    return
  fi

  printf '      - name: "%s"\n        version: "%s"\n        digest: "sha256:%s"\n' \
    "$COORDINATE" "$RELEASE_VERSION" "$(sha256 "$FILE")"
}

{
  printf 'release: "%s"\n' "$RELEASE_VERSION"
  printf 'generated_at: "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'components:\n'
  printf '  "%s":\n' "$COORDINATE"
  printf '    repo: "%s"\n' "$(repo_path)"
  printf '    commit: "%s"\n' "$CI_COMMIT_SHA"
  printf '    tag: "%s"\n' "$CI_COMMIT_TAG"
  printf '    artifacts:\n'
  artifact
} >"$OUT"

echo "wrote ${OUT}" >&2
