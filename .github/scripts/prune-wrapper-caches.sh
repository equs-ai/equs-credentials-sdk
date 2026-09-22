#!/usr/bin/env bash
# Usage: prune-wrapper-caches.sh
# Deletes this run's wrapper-* caches, plus any left behind by runs that were
# cancelled before their own cleanup could run. They are keyed on a commit sha
# and can never be restored by a later run.
set -euo pipefail

repo="${GITHUB_REPOSITORY:?}"
cutoff=$(date -u -d '3 hours ago' +%Y-%m-%dT%H:%M:%SZ)

drop() {
  local key="$1"
  if out=$(gh cache delete "$key" --repo "$repo" 2>&1); then
    echo "deleted $key"
  elif grep -qi "no caches found\|not found" <<<"$out"; then
    :
  else
    echo "failed to delete $key: $out" >&2
    return 1
  fi
}

for w in nodejs wasm uniffi swift askar; do
  drop "wrapper-$w-${GITHUB_SHA:?}"
done

gh cache list --repo "$repo" --limit 100 --json key,createdAt \
  --jq ".[] | select(.key | startswith(\"wrapper-\")) | select(.createdAt < \"$cutoff\") | .key" \
  | sort -u | while read -r key; do drop "$key"; done
