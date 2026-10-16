# oid4vc/verifier/src — Context

## Purpose
Runnable demo binary implementing the Verifier role in a full OID4VP flow. Exposes actix-web endpoints to initiate authorization requests, receive presentation responses (direct_post / direct_post.jwt), and verify the submitted VP.

## Files

| File | Role |
|------|------|
| `main.rs` | Entry point: wires `LocalKms`, `ReqwestClient`, `Verifier`; registers handlers for `/authorize`, `/post`, and `/transaction-data`; verifies presentations using DCQL or PresentationExchange; supports transaction data flows |

## Key types / traits
- Uses `vc::oid4vp::Verifier` from `equs_sdk`.
- `PresentationSession` — tracks in-progress verification requests.
- Supports `ResponseMode::DirectPostJwt` and `ResponseMode::DirectPost`.
- `shared::AuthRequestQuery` — controls query type (DCQL vs PresentationExchange) per request.

## Dependencies
- Depends on: `equs_sdk` (oid4vp, dcql, kms, inmem, reqwest, storage, vc::core, crypto), `shared` (sibling lib crate), `actix-web`, `tokio`
- Used by: developers demonstrating the verifier role end-to-end

## Constraints
- Demo / development use only; connects to a locally running holder.
- The `delegate-sd-jwt` Cargo feature switches `/request_uri` to the dSD-JWT delegation
  demo (selected at compile time via `cfg!(feature = "delegate-sd-jwt")`): it requests a
  voucher (`shared::voucher::voucher_dcql`) bound to a freshly generated `purchase_id`, with
  no transaction data, over `direct_post`. An empty transaction-data set is conveyed as
  `None` to verification (an empty `Some(..)` would expect hashes that are never sent).
  This feature forwards to `equs-credentials-sdk/delegate-sd-jwt` (→ `sd-jwt-rs/delegate`): the Merchant
  must verify the delegation chain, and `sd-jwt-rs` gates chain-aware verification behind that
  feature, so a local-only toggle would leave the Merchant unable to verify the dSD-JWT+KB.
