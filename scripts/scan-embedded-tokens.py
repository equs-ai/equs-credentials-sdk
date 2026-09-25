#!/usr/bin/env python3
"""Scan git-tracked files for embedded JWT/JWE compact serializations and
private key material.

Ports the method used by docs/security/2026-09-24-embedded-token-audit.md into
a checked-in, machine-checkable gate:

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
-- they just do not affect the exit code. This is what lets a known, accepted
exception (see below) stay visible without being a gate failure.

Known, accepted exception: demos/multi-thread/src/main.rs and
demos/oid4vc/issuer/src/main.rs each embed one expired token for a localhost
Keycloak realm. Both are read at runtime by validate_scope -> decode_unverified
to check the `scope` claim, so replacing them with placeholders breaks
credential issuance in the demo. This was verified against the code and
accepted -- see docs/superpowers/plans/2026-09-25-migrate-committed-tokens-to-fixtures.md,
Task 7. `demos/` is therefore never passed to --fail-on, but the scan still
reports these two hits, tagged as accepted exceptions, so nobody mistakes the
silence for the directory being clean.
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

PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----")

KNOWN_EXCEPTIONS = {
    "demos/multi-thread/src/main.rs": (
        "expired localhost Keycloak token, read via validate_scope -> "
        "decode_unverified for the `scope` claim; a placeholder breaks "
        "credential issuance in the demo (accepted, see Task 7)"
    ),
    "demos/oid4vc/issuer/src/main.rs": (
        "expired localhost Keycloak token, read via validate_scope -> "
        "decode_unverified for the `scope` claim; a placeholder breaks "
        "credential issuance in the demo (accepted, see Task 7)"
    ),
}


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


def git_tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout
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


@dataclass
class Normalized:
    """`text` with backslash-newline continuations collapsed, plus enough of
    a map to translate an offset in `text` back to the original file so
    reported line numbers point at a real line."""

    text: str
    original: str
    # (offset_in_normalized, offset_in_original) breakpoints, strictly
    # increasing in both fields; between two consecutive breakpoints the two
    # texts are identical, so the offset delta is constant there.
    breakpoints: list[tuple[int, int]]

    def original_offset(self, norm_offset: int) -> int:
        idx = bisect.bisect_right(self.breakpoints, (norm_offset, float("inf"))) - 1
        idx = max(0, idx)
        norm_bp, orig_bp = self.breakpoints[idx]
        return orig_bp + (norm_offset - norm_bp)

    def line_at(self, norm_offset: int) -> int:
        return line_of(self.original, self.original_offset(norm_offset))


def normalize(text: str) -> Normalized:
    parts = []
    breakpoints = [(0, 0)]
    last_end = 0
    out_len = 0
    for match in LINE_CONTINUATION_RE.finditer(text):
        chunk = text[last_end : match.start()]
        parts.append(chunk)
        out_len += len(chunk)
        breakpoints.append((out_len, match.end()))
        last_end = match.end()
    parts.append(text[last_end:])
    return Normalized(text="".join(parts), original=text, breakpoints=breakpoints)


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

    result = scan()

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

    known_hits = [
        h for h in result.token_hits if h.path in KNOWN_EXCEPTIONS
    ] + [h for h in result.key_hits if h.path in KNOWN_EXCEPTIONS]
    if known_hits:
        print(
            "Known accepted exceptions (demos/, not covered by --fail-on -- "
            "see the module docstring for why):"
        )
        for hit in sorted(known_hits, key=lambda h: (h.path, h.line)):
            reason = KNOWN_EXCEPTIONS[hit.path]
            if isinstance(hit, TokenHit):
                print(f"  {hit.path}:{hit.line}: {hit.kind} token, {hit.classification} -- {reason}")
            else:
                print(f"  {hit.path}:{hit.line}: {hit.kind} ({hit.detail}) -- {reason}")
        print()

    all_hits = sorted(
        result.token_hits + result.key_hits, key=lambda h: (h.path, h.line)
    )
    print(f"All hits ({len(all_hits)}):")
    if not all_hits:
        print("  (none)")
    for hit in all_hits:
        tag = " [known accepted exception]" if hit.path in KNOWN_EXCEPTIONS else ""
        if isinstance(hit, TokenHit):
            exp_str = f", exp={hit.exp}" if hit.exp is not None else ""
            print(f"  {hit.path}:{hit.line}: {hit.kind} token, {hit.classification}{exp_str}{tag}")
        else:
            print(f"  {hit.path}:{hit.line}: {hit.kind} ({hit.detail}){tag}")
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
