#!/usr/bin/env bash
# Renders the release manifest for one crate's release. The digest is the
# sha256 of the .crate tarball `cargo package` builds from this commit — no
# registry calls, so the manifest depends on nothing but the checkout.
set -euo pipefail

CRATE="${1:?usage: release_manifest.sh <crate> [output]}"
OUT="${2:-release-manifest.yaml}"

: "${CI_COMMIT_TAG:?}"
: "${CI_COMMIT_SHA:?}"

# The macro crate's tag carries a prefix, so its release version is passed in.
RELEASE_VERSION="${RELEASE_VERSION:-$CI_COMMIT_TAG}"

# Extra `cargo package` flags, e.g. --allow-dirty for a local run outside CI.
read -r -a PACKAGE_FLAGS <<<"${RELEASE_MANIFEST_PACKAGE_FLAGS:-}"

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

crate_version() {
  cargo metadata --no-deps --format-version 1 |
    jq -r --arg c "$CRATE" '.packages[] | select(.name == $c) | .version'
}

VERSION=$(crate_version)
[ -n "$VERSION" ] || { echo "no workspace package named ${CRATE}" >&2; exit 1; }
[ "$VERSION" = "$RELEASE_VERSION" ] ||
  echo "warning: ${CRATE} is ${VERSION}, release is ${RELEASE_VERSION}" >&2

artifact() {
  local crate_file="target/package/${CRATE}-${VERSION}.crate"

  if ! cargo package --locked --no-verify -p "$CRATE" "${PACKAGE_FLAGS[@]}" >/dev/null 2>&1 ||
    [ ! -f "$crate_file" ]; then
    echo "warning: cargo package failed for ${CRATE} ${VERSION}" >&2
    printf '      - name: "%s"\n        version: "%s"\n        digest: null\n' "$CRATE" "$VERSION"
    return
  fi

  printf '      - name: "%s"\n        version: "%s"\n        digest: "sha256:%s"\n' \
    "$CRATE" "$VERSION" "$(sha256 "$crate_file")"
}

{
  printf 'release: "%s"\n' "$RELEASE_VERSION"
  printf 'generated_at: "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'components:\n'
  printf '  %s:\n' "$CRATE"
  printf '    repo: "%s"\n' "$(repo_path)"
  printf '    commit: "%s"\n' "$CI_COMMIT_SHA"
  printf '    tag: "%s"\n' "$CI_COMMIT_TAG"
  printf '    artifacts:\n'
  artifact
} >"$OUT"

echo "wrote ${OUT}" >&2
