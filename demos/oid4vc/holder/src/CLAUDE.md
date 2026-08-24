# oid4vc/holder/src — Context

## Purpose
Runnable demo binary implementing the Holder role in a full OID4VCI + OID4VP flow. Accepts credential offers via terminal input, performs the OID4VCI authorization and credential issuance flow, stores the resulting credential, and presents it in an OID4VP flow when requested by a verifier.

## Files

| File | Role |
|------|------|
| `main.rs` | Entry point: wires `LocalKms`, `InMemVault`, `ReqwestClient`; drives OID4VCI pre-authorized-code and authorization-code flows; handles OID4VP `AuthorizationRequest` and builds the presentation response |
| `user_input.rs` | CLI prompt helpers for reading credential offer URLs and user consent from stdin |

## Key types / traits
- Uses `vc::oid4vci::Holder` and `vc::oid4vp::Holder` directly from `equs_sdk`.
- Uses `DCQL` and `PresentationDefinition` to resolve presentation queries.
- `shared::AuthRequestQuery` — parsed from verifier's authorization request URL.

## Dependencies
- Depends on: `equs_sdk` (oid4vci, oid4vp, dcql, kms, inmem, reqwest, presentation_exchange), `shared` (sibling lib crate), `actix-web` (serves the redirect endpoint), `tokio`
- Used by: developers demonstrating the holder role end-to-end

## Constraints
- Demo / development use only; connects to a locally running issuer and verifier.
- The `delegate-sd-jwt` Cargo feature (`-F delegate-sd-jwt`) makes the issuance flow
  additionally request the `voucher_cred` (for the dSD-JWT delegation demo), gated at
  compile time via `#[cfg(feature = "delegate-sd-jwt")]`. The presentation flow is
  unchanged: a `delegate` transaction-data item in the auth request is handled by the
  standard OID4VP present path.
