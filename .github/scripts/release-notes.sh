#!/usr/bin/env bash
# Usage: bash release-notes.sh <owner/repo> <tag>
# Renders the annotated tag's `- [kind] text: #PR` lines as Markdown, one heading
# per kind. Prints nothing for a lightweight tag.
set -euo pipefail

repo=$1 tag=$2
sha=$(gh api "repos/$repo/git/refs/tags/$tag" --jq 'select(.object.type == "tag") | .object.sha')
[ -n "$sha" ] || exit 0

titles=("Breaking changes" "New" "Fixes" "Security" "Maintenance" "Other")
sections=("" "" "" "" "" "")
lead=""
first=1
while IFS= read -r line; do
  [[ "$line" == "-----BEGIN "* ]] && break
  if [ "$first" = 1 ]; then first=0; continue; fi
  if [[ "$line" =~ ^-\ \[([a-z]+)\]\ (.*)$ ]]; then
    kind=${BASH_REMATCH[1]} text=${BASH_REMATCH[2]}
    [[ "$text" =~ ^(.*):\ (#[0-9]+(,\ #[0-9]+)*)$ ]] && text="${BASH_REMATCH[1]} (${BASH_REMATCH[2]})"
    case $kind in
      break) i=0 ;; feat) i=1 ;; fix) i=2 ;; sec | security) i=3 ;; chore | deps) i=4 ;; *) i=5 ;;
    esac
    sections[i]+="- $text"$'\n'
  elif [ -n "$line" ]; then
    lead+="$line"$'\n'
  fi
done < <(gh api "repos/$repo/git/tags/$sha" --jq .message)

[ -z "$lead" ] || printf '%s\n' "$lead"
for i in "${!titles[@]}"; do
  [ -z "${sections[i]}" ] || printf '## %s\n\n%s\n' "${titles[i]}" "${sections[i]}"
done
