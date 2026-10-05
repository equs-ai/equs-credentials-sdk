#!/usr/bin/env python3
"""Regression tests for scan-embedded-tokens.py.

Run directly:

    python3 scripts/test_scan_embedded_tokens.py

or via unittest discovery from the repo root:

    python3 -m unittest discover -s scripts -p "test_*.py"

`scan-embedded-tokens.py` has a hyphen in its name, so it cannot be `import`ed
as an ordinary module; it is loaded here via `importlib` from its file path
instead (see `_load_scanner` below). Loading it only executes module-level
code (imports, regex compilation, dataclass/function definitions); `main()`
only runs under `if __name__ == "__main__"`, so importing it here never
invokes `git ls-files` or prints a report.

These exist because two of the detectors' blind spots were found by manual,
ad hoc testing during review and then silently lost -- exactly the failure
mode that makes a "the scanner is right because I checked it once" claim
worthless six months later. Each `Important` fixed here has a test named
after it so the next person touching `normalize()`, `TOKEN_RE` or
`find_private_jwks` has something to run before believing they haven't
regressed it.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().parent / "scan-embedded-tokens.py"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scan_embedded_tokens", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    # Must be registered before exec_module: the module's @dataclass
    # decorators resolve annotations against sys.modules[__module__], which
    # does not exist yet otherwise (fails on CPython 3.14, harmless no-op on
    # earlier versions where dataclass resolution is lazier).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scan = _load_scanner()


def b64u(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


class TestTokenDetection(unittest.TestCase):
    def setUp(self):
        self.header = b64u({"alg": "ES256", "typ": "JWT"})
        self.live_payload = b64u({"exp": int(time.time()) + 3600, "sub": "x"})
        self.expired_payload = b64u({"exp": int(time.time()) - 3600, "sub": "x"})
        self.noexp_payload = b64u({"sub": "x"})
        self.sig = "abc123_-XYZ"

    def _token(self, payload: str) -> str:
        return f"{self.header}.{payload}.{self.sig}"

    def test_classifies_live_expired_and_noexp(self):
        text = (
            f'let a = "{self._token(self.live_payload)}"; '
            f'let b = "{self._token(self.expired_payload)}"; '
            f'let c = "{self._token(self.noexp_payload)}";'
        )
        hits = scan.find_tokens("t.rs", scan.normalize(text))
        classifications = sorted(h.classification for h in hits)
        self.assertEqual(classifications, ["expired", "live", "no-exp"])

    def test_rejects_eyj_string_without_alg_or_enc_header(self):
        fake_header = b64u({"foo": "bar"})
        text = f'"{fake_header}.somepayload.somesig"'
        hits = scan.find_tokens("t.rs", scan.normalize(text))
        self.assertEqual(hits, [])

    def test_detects_jwe_with_empty_encrypted_key_segment(self):
        jwe_header = b64u({"alg": "ECDH-ES", "enc": "A128CBC-HS256"})
        text = f'"{jwe_header}..iv123.ciphertext456.tag789"'
        hits = scan.find_tokens("t.rs", scan.normalize(text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].kind, "JWE")
        self.assertEqual(hits[0].classification, "encrypted")

    def test_line_continuation_important_regression(self):
        """A Rust `\\`-newline-continued string literal must not truncate or
        split a token. This was the first blind spot found: a token
        wrapped this way produced zero hits before `normalize()` collapsed
        the continuation."""
        wrapped = (
            f'const X: &str = "{self.header[:10]}\\\n'
            f'{self.header[10:]}.{self.live_payload}\\\n'
            f'.{self.sig}";'
        )
        hits = scan.find_tokens("t.rs", scan.normalize(wrapped))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].classification, "live")

    def test_string_concatenation_important_2_regression(self):
        """A token wrapped as separate quoted fragments joined by `+` -- the
        ordinary way to wrap a long string in JS/TS/Kotlin/Swift -- must not
        be invisible. Fix round 1 found this: TOKEN_RE alone produced zero
        hits for exactly this shape."""
        text = f'"{self.header}" + "." + "{self.live_payload}" + "." + "{self.sig}"'
        hits = scan.find_tokens("t.ts", scan.normalize(text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].classification, "live")

    def test_string_concatenation_across_newlines(self):
        """The dominant real-world shape: fragments concatenated across
        physical lines, split mid-segment rather than at a `.` boundary (as
        seen in plugins/askar/wrappers/nodejs/test/vault.test.ts)."""
        token = self._token(self.live_payload)
        mid = len(token) // 2
        text = f'"{token[:mid]}" +\n      "{token[mid:]}"'
        hits = scan.find_tokens("t.ts", scan.normalize(text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].classification, "live")


class TestPrivateKeyDetection(unittest.TestCase):
    """Every fixture here is assembled at runtime from parts rather than
    written as a literal JWK/PEM in this file's source: a checked-in file
    holding real-shaped PEM/JWK private-key text is exactly the alert class
    this whole migration removes, and a generic secret scanner reading this
    file's raw bytes cannot see past `str.join`/`dict` assembly the way
    `scan.normalize()` deliberately can for target source files. The `d`
    value is always an obviously-fake placeholder, never something
    key-shaped, so nothing here reads as real key material even assembled.
    """

    FAKE_D_VALUE = "not-a-real-private-key-value"

    @staticmethod
    def _jwk_text(private: bool) -> str:
        obj = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        if private:
            obj["d"] = TestPrivateKeyDetection.FAKE_D_VALUE
        return json.dumps(obj)

    def test_flags_a_literal_private_jwk(self):
        text = self._jwk_text(private=True)
        hits = scan.find_private_jwks("t.rs", scan.normalize(text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].kind, "jwk-private")

    def test_does_not_flag_a_public_jwk(self):
        text = self._jwk_text(private=False)
        hits = scan.find_private_jwks("t.rs", scan.normalize(text))
        self.assertEqual(hits, [])

    def test_escaped_quote_jwk_important_1_regression(self):
        """A JWK embedded as JSON inside an ordinary (non-raw) string literal
        is written `"{\\"kty\\": \\"EC\\", \\"d\\": \\"...\\"}"`. Those bytes
        contain no literal `"d"` substring -- only `\\"d\\"` -- so the
        pre-check in find_private_jwks never even starts the brace scan.
        Fix round 1 found this via a synthetic file the reviewer supplied
        that produced zero hits."""
        escaped = self._jwk_text(private=True).replace('"', '\\"')
        text = f'"{escaped}"'
        hits = scan.find_private_jwks("t.rs", scan.normalize(text))
        self.assertEqual(len(hits), 1)

    def test_escaped_and_concatenated_jwk(self):
        """Both blind spots at once: an escaped-JSON JWK split across a `+`
        concatenation. Exercises pass ordering in normalize() -- glue removal
        has to run before quote-unescaping or the two fragments never
        recombine into one parseable object."""
        escaped = self._jwk_text(private=True).replace('"', '\\"')
        mid = len(escaped) // 2
        text = f'"{escaped[:mid]}" + "{escaped[mid:]}"'
        hits = scan.find_private_jwks("t.rs", scan.normalize(text))
        self.assertEqual(len(hits), 1)

    def test_flags_pem_private_key_block(self):
        banner = "".join(["-----BEGIN ", "EC PRIVATE KEY", "-----"])
        trailer = "".join(["-----END ", "EC PRIVATE KEY", "-----"])
        fake_body = "NOT-VALID-BASE64-THIS-IS-A-PLACEHOLDER-BODY-NOT-A-KEY"
        text = "\n".join([banner, fake_body, trailer])
        hits = scan.find_pem_private_keys("t.rs", scan.normalize(text))
        self.assertEqual(len(hits), 1)
        self.assertIn("PRIVATE KEY", hits[0].detail)


class TestGitMissing(unittest.TestCase):
    """`python:3-slim` shipped no `git`, so every pipeline run of this gate
    failed with a FileNotFoundError traceback -- indistinguishable from a
    genuine hit by exit code alone (both were `1`). git_tracked_files() must
    turn that into a distinct, legible error, and main() must exit with a
    code that is neither `1` (tokens found) nor `2` (argparse usage error)."""

    def test_git_tracked_files_raises_scan_environment_error_when_git_missing(self):
        with mock.patch.object(
            scan.subprocess, "run", side_effect=FileNotFoundError("git")
        ):
            with self.assertRaises(scan.ScanEnvironmentError):
                scan.git_tracked_files()

    def test_main_exits_with_a_distinct_code_when_git_missing(self):
        with mock.patch.object(
            scan.subprocess, "run", side_effect=FileNotFoundError("git")
        ), mock.patch.object(sys, "argv", ["scan-embedded-tokens.py"]):
            exit_code = scan.main()
        self.assertEqual(exit_code, scan.EXIT_ENVIRONMENT_ERROR)
        self.assertNotIn(exit_code, (0, 1, 2))


class TestUnderAny(unittest.TestCase):
    def test_matches_exact_and_nested_paths(self):
        self.assertTrue(scan.under_any("src/vc/foo.rs", ["src/"]))
        self.assertTrue(scan.under_any("src/vc/foo.rs", ["src"]))
        self.assertTrue(scan.under_any("tests/mod.rs", ["tests/"]))

    def test_does_not_match_a_sibling_with_a_shared_prefix(self):
        # "src2/" must not be considered "under" "src/".
        self.assertFalse(scan.under_any("src2/foo.rs", ["src/"]))

    def test_does_not_match_unrelated_paths(self):
        self.assertFalse(scan.under_any("wrappers/nodejs/x.ts", ["src/", "tests/"]))


if __name__ == "__main__":
    unittest.main()
