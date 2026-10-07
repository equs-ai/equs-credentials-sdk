# fixtures — Context

## Purpose
Provides static test data and factory functions used across integration tests: metadata
configurations, sample claims, access tokens, and reusable OID4VP test-case builders.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| mod.rs   | Top-level fixture module; exports `AUTHZ_URL`, `ISSUER_URL`, `SCOPE`, `VC_TYPE`, `VERIFIER_ID` constants, `access_token()` (a Keycloak-shaped `RS256` token generated through `test_fixtures`), sample metadata builders (`sample_issuer_metadata`, `sample_authorization_metadata`), claim constructors for SD-JWT and JSON-LD, and `find_vcs_to_present` helper. |
| oid4vp.rs | OID4VP-specific fixtures: `Oid4VpTestCase` / `Oid4VpTestCredential` parameterised scenario builders (single JSON-LD, single SD-JWT, multiple SD-JWT, DCQL), `MockNonceHandler`, `create_vc` helper, and the generated mDL fixtures: `mdl_iaca` (self-signed IACA for a key), `mdl_chain` (IACA, DS certificate and DS key), `mdl_vp_token` (presentation issued under a DS, bound to `MDL_NONCE` and `MDL_CLIENT_ID`). |

## Key types / traits (if applicable)
- `Oid4VpTestCase` — bundles credentials, `PresentationDefinition`, optional `DCQL`, and a `ValidateClaimsFunc` callback.
- `Oid4VpTestCredential` — pairs an `Oid4VpTestCredentialFormat` (SdJwt or LdpVc) with claims.
- `MockNonceHandler` — always returns a fixed nonce and validates any nonce as true.

## Dependencies
- Depends on: `equs_sdk` (vault, vc, did, nonce, crypto), `test_fixtures`, `serde_json`, `url`, `time`, `openid4vp`, `ssi`
- Used by: `tests/e2e/vc_oid4vci.rs`, `tests/e2e/vc_oid4vp.rs`, `tests/e2e/waci_aries.rs`, `tests/e2e/custom_did_resolvers.rs`

## Constraints
- `oid4vp.rs` re-uses `create_did_keymetadata_keyhandle` from `utils/helpers/mod.rs`.
