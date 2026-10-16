# helpers — Context

## Purpose
Provides reusable async helper functions for constructing DID/key material and protocol
participants (OID4VCI issuer, holder) in integration tests.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| mod.rs     | Declares the `oid4vci` sub-module and exports `create_did_keymetadata_keyhandle`, which generates a P-256 key in `LocalKms`, derives its `did:key`, and resolves the first verification method URL. |
| oid4vci.rs | Provides `build_issuer` (creates an `IssuerBuilder`-based issuer with optional token introspection), `build_holder` (creates an `HolderBuilder`-based holder with `CredentialExtraVerification`), and `setup_http_static_handlers` (registers `.well-known` endpoints on `HttpClientEmulator`). |

## Key types / traits (if applicable)
- Builds instances of `equs_sdk::vc::oid4vci::{Issuer, Holder}` using `LocalKms` + `InMemVault`.

## Dependencies
- Depends on: `equs_sdk` (inmem, kms, vc::oid4vci), `utils::http::HttpClientEmulator`, `utils::fixtures`
- Used by: `tests/e2e/vc_oid4vci.rs`, `tests/e2e/custom_did_resolvers.rs`, `tests/utils/fixtures/oid4vp.rs`
