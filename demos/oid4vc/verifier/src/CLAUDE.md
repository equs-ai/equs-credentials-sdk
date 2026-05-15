# oid4vc/verifier/src — Context

## Purpose
Runnable demo binary implementing the Verifier role in a full OID4VP flow. Exposes actix-web endpoints to initiate authorization requests, receive presentation responses (direct_post / direct_post.jwt), and verify the submitted VP.

## Files

| File | Role |
|------|------|
| `main.rs` | Entry point: wires `LocalKms`, `ReqwestClient`, `Verifier`; registers handlers for `/authorize`, `/post`, and `/transaction-data`; verifies presentations using DCQL or PresentationExchange; supports transaction data flows |

## Key types / traits
- Uses `vc::oid4vp::Verifier` from `agent_sdk`.
- `PresentationSession` — tracks in-progress verification requests.
- Supports `ResponseMode::DirectPostJwt` and `ResponseMode::DirectPost`.
- `shared::AuthRequestQuery` — controls query type (DCQL vs PresentationExchange) per request.

## Dependencies
- Depends on: `agent_sdk` (oid4vp, dcql, kms, inmem, reqwest, storage, vc::core, crypto), `shared` (sibling lib crate), `actix-web`, `tokio`
- Used by: developers demonstrating the verifier role end-to-end

## Constraints
- Demo / development use only; connects to a locally running holder.
