# trust — Context

## Purpose
Node bindings for `equs_sdk::vc::trust`. Issuer-trust configuration itself (`TrustAnchor`, mode, classification) is set
on the verifier builder in `vc::oid4vp::builder`; this module holds the stand-alone functions.

## Files

| File | Role |
|------|------|
| `mod.rs` | Declares `list` and `trusted_authorities`. |
| `list.rs` | `exportTrustList(url, kind, options?, httpClient?)` over the SDK's `export_trust_list` (built-in hardened client) or, given a JS `HttpClient`, `export_trust_list_with_client`. `kind` is parsed by the SDK's `trust_list_kind`; `documentTimeoutSeconds` bounds each document. Returns `TrustListExport` with dates as RFC 3339 strings and roles / skip reasons as snake_case strings; fails with an `EqusSdkError` whose code is a `TrustListError` (PascalCase, e.g. `SignerNotTrusted`) and whose message starts with `trust_list_<reason>`. |
| `trusted_authorities.rs` | `deriveTrustedAuthorityAkis(anchors)` over the SDK's `derive_trusted_authority_akis`: the DCQL `aki` values (base64url) for a verifier's issuer anchors, with the anchors that gave none listed in `skipped`. |
