#!/usr/bin/env bash
# Usage: coverage-badge.sh <percent>
set -euo pipefail

pct="${1:?percent required}"
branch="badges"
rel=".badges/${GITHUB_REF_NAME}/coverage.svg"
url="https://x-access-token:${GITHUB_TOKEN:?token required}@github.com/${GITHUB_REPOSITORY}"

whole="${pct%%.*}"
if   [ "$whole" -ge 90 ]; then colour="#4c1"
elif [ "$whole" -ge 75 ]; then colour="#97ca00"
elif [ "$whole" -ge 60 ]; then colour="#dfb317"
else                           colour="#e05d44"
fi

work="$RUNNER_TEMP/coverage-badge"
rm -rf "$work"
if ! git clone --depth 1 --branch "$branch" "$url" "$work" 2>/dev/null; then
  git clone --depth 1 "$url" "$work"
  git -C "$work" checkout --orphan "$branch"
  git -C "$work" rm -rqf .
fi

mkdir -p "$work/$(dirname "$rel")"
cat > "$work/$rel" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="114" height="20" role="img" aria-label="coverage: ${pct}%">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="114" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="69" height="20" fill="#555"/>
    <rect x="69" width="45" height="20" fill="${colour}"/>
    <rect width="114" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text x="355" y="140" transform="scale(.1)" fill="#010101" fill-opacity=".3">coverage</text>
    <text x="355" y="130" transform="scale(.1)">coverage</text>
    <text x="905" y="140" transform="scale(.1)" fill="#010101" fill-opacity=".3">${pct}%</text>
    <text x="905" y="130" transform="scale(.1)">${pct}%</text>
  </g>
</svg>
SVG

git -C "$work" add "$rel"
git -C "$work" diff --cached --quiet && { echo "coverage badge unchanged at ${pct}%"; exit 0; }
git -C "$work" -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -qm "coverage: ${pct}%"
git -C "$work" push -q origin "$branch"
echo "coverage badge published at ${pct}%"
