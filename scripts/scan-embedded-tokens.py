#!/usr/bin/env python3
"""Scan git-tracked files for embedded JWT/JWE compact serializations and
private key material.

A checked-in, machine-checkable gate:

  - walks `git ls-files` (tracked files only, so build output and IDE state
    are never scanned);
  - finds `eyJ...` runs that look like a compact JWS/JWE serialization and
    base64url-decodes the first segment to confirm it really is a token
    header (an `alg` or `enc` member), not an incidental base64-ish string;
  - classifies each confirmed token by its `exp` claim (live / expired /
    no-exp), or as encrypted (JWE) when the payload is not readable;
  - separately finds JWK objects that carry a `d` member (private key
    material) and PEM `PRIVATE KEY` blocks.

`--fail-on PATH [PATH ...]` exits non-zero when any hit (token or key) falls
under one of the given paths. Paths not listed are still scanned and reported
-- they just do not affect the exit code.

Known limitations -- shapes this scanner does NOT see, stated here rather than
implied by silence:

  - JWS JSON Serialization (`{"payload": ..., "signatures": [{"protected":
    ..., "signature": ...}]}`) is spec-legal JOSE and is not detected at all.
    Nothing in this repo currently uses it; if that changes, this scanner
    needs a second detector, not a tweak to TOKEN_RE.
  - Only three encodings of a split/obfuscated string are normalized before
    matching: a Rust backslash-newline continuation, a `"..." + "..."`-style
    concatenation (the common JS/TS/Kotlin/Swift way to wrap a long string,
    handled across `+`, whitespace and newlines), and a `\"`-escaped JSON
    literal (the common way a JWK ends up embedded in an ordinary, non-raw
    string literal). A token or key hidden by some other transform --
    string-building via `.join(...)`, computed/interpolated strings,
    intentional character-swapping, a base64-of-base64 wrapper, a genuinely
    binary file this scanner failed to decode as UTF-8 -- is invisible to it.
  - It reads `git ls-files` tracked content only. A token that exists solely
    in git history (an old commit, a stash, a reflog entry) is not scanned.
"""

from __future__ import annotations

import argparse
import base64
import bisect
import binascii
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# A compact JWS is header.payload.signature (2 dots); a compact JWE is
# header.encrypted_key.iv.ciphertext.tag (4 dots). Either the encrypted key or
# the signature segment may be empty ("dir"/ECDH-ES key agreement, or "alg":
# "none"), so segments after the header are matched with `*` rather than `+`.
TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*){1,4}")

# Rust (and C, and a few other languages) lets a string literal continue onto
# the next physical line by ending the line with `\`: the backslash, the
# newline, and the following run of indentation are all dropped from the
# string's value. A long base64url run wrapped that way -- one of the exact
# shapes the fixtures in this repo used before their migration -- would
# otherwise split a real token into pieces too short to match TOKEN_RE, or
# split a segment across the `.` boundary so the header never lines up with
# its payload. Collapsing those continuations before matching is what makes
# the scan trustworthy against a token someone wraps at 100 columns.
LINE_CONTINUATION_RE = re.compile(r"\\\r?\n[ \t]*")

# JS/TS/Kotlin/Swift have no line-continuation syntax, so the idiomatic way to
# wrap a long string there is concatenation: `"eyJhbGci..." +\n  "eyJzdWI..."`,
# or splitting exactly at a `.` boundary as `"eyJhbGci..." + "." + "eyJzdWI..."`.
# Either way the two fragments are two separate string literals in the raw
# text, with a closing quote, `+`, and opening quote between them -- not
# contiguous base64url/dot text -- so TOKEN_RE cannot see across the join
# unmodified. This matches that glue (quote, optional whitespace/newlines,
# `+`, optional whitespace/newlines, quote) so removing it directly abuts the
# two fragments' contents, which is exactly what the source represents as one
# logical string. Quote characters do not need to match on both sides.
STRING_CONCAT_GLUE_RE = re.compile(r"""["'`]\s*\+\s*["'`]""")

# A JWK embedded as JSON *inside* an ordinary (non-raw) string literal is
# written with every inner quote backslash-escaped:
# `"{\"kty\": \"EC\", \"d\": \"...\"}"`. Those bytes contain no literal `"d"`
# substring at all -- only `\"d\"` -- so neither the cheap pre-check in
# find_private_jwks nor json.loads ever sees valid JSON. Un-escaping `\"` to
# `"` before matching turns that back into ordinary embedded JSON. This is
# applied file-wide rather than only inside detected string spans (finding
# "the string literal boundaries" first would need a real language-aware
# lexer per source language); the risk is an unrelated `\"` elsewhere in the
# same file also being unescaped, which is harmless here since nothing else
# in this scanner treats a bare `"` as meaningful outside a JSON parse attempt.
ESCAPED_QUOTE_RE = re.compile(r'\\"')

PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----")

# `1` is what `--fail-on` returns for a genuine hit; this must never collide
# with it, or a broken environment reads as a security finding by exit code
# alone. `2` is argparse's own usage-error code, so this skips that too.
EXIT_ENVIRONMENT_ERROR = 3


@dataclass
class TokenHit:
    path: str
    line: int
    kind: str  # "JWS" | "JWE" | "unsecured"
    classification: str  # "live" | "expired" | "no-exp" | "encrypted"
    exp: int | None = None


@dataclass
class KeyHit:
    path: str
    line: int
    kind: str  # "jwk-private" | "pem-private-key"
    detail: str = ""


@dataclass
class ScanResult:
    files_scanned: int = 0
    token_hits: list[TokenHit] = field(default_factory=list)
    key_hits: list[KeyHit] = field(default_factory=list)


class ScanEnvironmentError(RuntimeError):
    """The scan cannot run because a tool it depends on is missing.

    Distinct from a real gate hit: `main()` maps this to `EXIT_ENVIRONMENT_ERROR`
    (not `1`, the same code `--fail-on` uses for "tokens found"), so a broken
    CI image reads as a broken CI image, not as a security finding."""


def git_tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except FileNotFoundError as e:
        raise ScanEnvironmentError(
            "git is not on PATH -- cannot enumerate tracked files"
        ) from e
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def b64url_decode(segment: str) -> bytes | None:
    if not segment:
        return None
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return None


def decode_json_segment(segment: str) -> dict | None:
    raw = b64url_decode(segment)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _pass_resolver(breakpoints: list[tuple[int, int]]):
    """Builds a function mapping an offset in this pass's output text back to
    an offset in this pass's input text, from (out_offset, in_offset)
    breakpoints that are strictly increasing in both fields. Between two
    consecutive breakpoints the two texts are identical, so the offset delta
    is constant there; a lookup past the last breakpoint (inside or after a
    replacement span) is clamped to that breakpoint's delta, which is not
    always exact but always lands in the right neighbourhood."""

    def resolve(out_offset: int) -> int:
        idx = bisect.bisect_right(breakpoints, (out_offset, float("inf"))) - 1
        idx = max(0, idx)
        out_bp, in_bp = breakpoints[idx]
        return in_bp + (out_offset - out_bp)

    return resolve


def _apply_pass(text: str, pattern: re.Pattern[str], replacement: str) -> tuple[str, object]:
    """Replaces every match of `pattern` in `text` with `replacement` and
    returns the new text plus a resolver from an offset in the new text back
    to an offset in `text`."""
    parts = []
    breakpoints = [(0, 0)]
    last_end = 0
    out_len = 0
    for match in pattern.finditer(text):
        chunk = text[last_end : match.start()]
        parts.append(chunk)
        out_len += len(chunk)
        parts.append(replacement)
        out_len += len(replacement)
        breakpoints.append((out_len, match.end()))
        last_end = match.end()
    parts.append(text[last_end:])
    return "".join(parts), _pass_resolver(breakpoints)


@dataclass
class Normalized:
    """`text` is `original` after every normalization pass below has run, in
    order. `resolve` maps an offset in `text` all the way back to an offset in
    `original`, composing each pass's own resolver, so reported line numbers
    point at a real line in the file on disk -- not at the synthetic text
    these passes matched against."""

    text: str
    original: str
    resolve: object  # Callable[[int], int]

    def line_at(self, norm_offset: int) -> int:
        return line_of(self.original, self.resolve(norm_offset))


# Applied in this order because later passes depend on earlier ones having
# already run: concatenation-glue removal must land segments contiguously
# before quote-unescaping can turn a `\"kty\"...\"d\"` embedded in two
# concatenated fragments into one parseable object (see STRING_CONCAT_GLUE_RE
# and ESCAPED_QUOTE_RE's own comments for a worked example of that ordering).
NORMALIZATION_PASSES: list[tuple[re.Pattern[str], str]] = [
    (LINE_CONTINUATION_RE, ""),
    (STRING_CONCAT_GLUE_RE, ""),
    (ESCAPED_QUOTE_RE, '"'),
]


def normalize(text: str) -> Normalized:
    resolvers = []
    current = text
    for pattern, replacement in NORMALIZATION_PASSES:
        current, resolve = _apply_pass(current, pattern, replacement)
        resolvers.append(resolve)

    def resolve_to_original(offset: int) -> int:
        for resolve in reversed(resolvers):
            offset = resolve(offset)
        return offset

    return Normalized(text=current, original=text, resolve=resolve_to_original)


def classify_token(header: dict, segments: list[str]) -> tuple[str, str, int | None]:
    """Returns (kind, classification, exp)."""
    is_jwe = "enc" in header or len(segments) == 5
    if is_jwe:
        return "JWE", "encrypted", None

    kind = "unsecured" if header.get("alg") == "none" else "JWS"
    payload = decode_json_segment(segments[1]) if len(segments) > 1 else None
    if payload is None or "exp" not in payload:
        return kind, "no-exp", None

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return kind, "no-exp", None

    now = time.time()
    return kind, ("live" if exp > now else "expired"), int(exp)


def find_tokens(path: str, norm: Normalized) -> list[TokenHit]:
    hits: list[TokenHit] = []
    text = norm.text
    if "eyJ" not in text:
        return hits
    for match in TOKEN_RE.finditer(text):
        segments = match.group(0).split(".")
        header = decode_json_segment(segments[0])
        if header is None or not ({"alg", "enc"} & header.keys()):
            continue
        kind, classification, exp = classify_token(header, segments)
        hits.append(
            TokenHit(
                path=path,
                line=norm.line_at(match.start()),
                kind=kind,
                classification=classification,
                exp=exp,
            )
        )
    return hits


def find_private_jwks(path: str, norm: Normalized) -> list[KeyHit]:
    hits: list[KeyHit] = []
    text = norm.text
    if '"d"' not in text or '"kty"' not in text:
        return hits
    decoder = json.JSONDecoder()
    search_from = 0
    while True:
        brace = text.find("{", search_from)
        if brace == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, brace)
        except json.JSONDecodeError:
            search_from = brace + 1
            continue
        if isinstance(obj, dict) and "d" in obj and "kty" in obj:
            hits.append(
                KeyHit(
                    path=path,
                    line=norm.line_at(brace),
                    kind="jwk-private",
                    detail=f"kty={obj.get('kty')!r}",
                )
            )
        search_from = max(end, brace + 1)
    return hits


def find_pem_private_keys(path: str, norm: Normalized) -> list[KeyHit]:
    hits: list[KeyHit] = []
    for match in PEM_PRIVATE_KEY_RE.finditer(norm.text):
        hits.append(
            KeyHit(
                path=path,
                line=norm.line_at(match.start()),
                kind="pem-private-key",
                detail=match.group(1).strip(),
            )
        )
    return hits


def scan() -> ScanResult:
    result = ScanResult()
    for rel_path in git_tracked_files():
        full_path = REPO_ROOT / rel_path
        if full_path.resolve() == Path(__file__).resolve():
            # The scanner's own source: its docstring and regexes mention
            # "eyJ" and PRIVATE KEY but embed no real token or key material.
            continue
        text = read_text(full_path)
        if text is None:
            continue
        result.files_scanned += 1
        norm = normalize(text)
        result.token_hits.extend(find_tokens(rel_path, norm))
        result.key_hits.extend(find_private_jwks(rel_path, norm))
        result.key_hits.extend(find_pem_private_keys(rel_path, norm))
    return result


def under_any(path: str, prefixes: list[str]) -> bool:
    norm = path if not path.startswith("./") else path[2:]
    for prefix in prefixes:
        prefix = prefix if not prefix.startswith("./") else prefix[2:]
        prefix = prefix.rstrip("/")
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fail-on",
        nargs="+",
        default=[],
        metavar="PATH",
        help="exit non-zero if any token or private key is found under these paths",
    )
    args = parser.parse_args()

    try:
        result = scan()
    except ScanEnvironmentError as e:
        print(f"Embedded token scan: ENVIRONMENT ERROR -- {e}", file=sys.stderr)
        return EXIT_ENVIRONMENT_ERROR

    token_counts: dict[str, int] = {}
    for hit in result.token_hits:
        token_counts[hit.classification] = token_counts.get(hit.classification, 0) + 1

    key_counts: dict[str, int] = {}
    for hit in result.key_hits:
        key_counts[hit.kind] = key_counts.get(hit.kind, 0) + 1

    print("Embedded token scan")
    print("====================")
    print(f"Scanned {result.files_scanned} git-tracked files.")
    print()
    print(
        f"Tokens found: {len(result.token_hits)} "
        f"(live: {token_counts.get('live', 0)}, "
        f"expired: {token_counts.get('expired', 0)}, "
        f"no-exp: {token_counts.get('no-exp', 0)}, "
        f"encrypted/JWE: {token_counts.get('encrypted', 0)})"
    )
    print(
        f"Private keys found: {len(result.key_hits)} "
        f"(JWK-with-d: {key_counts.get('jwk-private', 0)}, "
        f"PEM-private-key: {key_counts.get('pem-private-key', 0)})"
    )
    print()

    all_hits = sorted(
        result.token_hits + result.key_hits, key=lambda h: (h.path, h.line)
    )
    print(f"All hits ({len(all_hits)}):")
    if not all_hits:
        print("  (none)")
    for hit in all_hits:
        if isinstance(hit, TokenHit):
            exp_str = f", exp={hit.exp}" if hit.exp is not None else ""
            print(f"  {hit.path}:{hit.line}: {hit.kind} token, {hit.classification}{exp_str}")
        else:
            print(f"  {hit.path}:{hit.line}: {hit.kind} ({hit.detail})")
    print()

    if args.fail_on:
        failing = [h for h in all_hits if under_any(h.path, args.fail_on)]
        print(f"--fail-on: {' '.join(args.fail_on)}")
        if failing:
            print(f"Result: FAIL ({len(failing)} hit(s) under --fail-on paths)")
            return 1
        print("Result: PASS (0 hits under --fail-on paths)")
        return 0

    print("--fail-on: (none given -- report only, exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
