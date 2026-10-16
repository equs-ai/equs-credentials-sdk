#!/usr/bin/env bash
# Renders the release manifest for one npm release. Each digest is the sha256
# of the tarball the publish job packed and handed to `npm publish` — no
# registry calls, so the manifest depends on nothing but the release's files.
set -euo pipefail

COMPONENT="${1:?usage: npm_release_manifest.sh <component> <output> <tarball-dir> <package>...}"
OUT="${2:?usage: npm_release_manifest.sh <component> <output> <tarball-dir> <package>...}"
DIR="${3:?usage: npm_release_manifest.sh <component> <output> <tarball-dir> <package>...}"
shift 3
[ "$#" -gt 0 ] || { echo "no packages given" >&2; exit 1; }

: "${CI_COMMIT_TAG:?}"
: "${CI_COMMIT_SHA:?}"

# npm tags carry a prefix, so the release version is passed in.
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
  local name="$1" file tarball version
  file="$(printf '%s' "${name#@}" | tr '/' '-')-${RELEASE_VERSION}.tgz"
  tarball=$(find "$DIR" -type f -name "$file" | head -1)

  if [ -z "$tarball" ]; then
    echo "warning: no tarball ${file} for ${name}" >&2
    printf '      - name: "%s"\n        version: "%s"\n        digest: null\n' "$name" "$RELEASE_VERSION"
    return
  fi

  version=$(tar -xzOf "$tarball" package/package.json | jq -r .version)
  [ "$version" = "$RELEASE_VERSION" ] ||
    echo "warning: ${name} is ${version}, release is ${RELEASE_VERSION}" >&2

  printf '      - name: "%s"\n        version: "%s"\n        digest: "sha256:%s"\n' \
    "$name" "$version" "$(sha256 "$tarball")"
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
  for name in "$@"; do artifact "$name"; done
} >"$OUT"

echo "wrote ${OUT}" >&2
