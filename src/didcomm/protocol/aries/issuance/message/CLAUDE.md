# message — Context

## Purpose
Defines all wire-format DIDComm message structs for the `issue-credential/3.0` protocol exchange, plus the `impl_ldp_vc_details_format!` macro for attaching/extracting LD-Proof VCs.

## Files

| File | Role |
|------|------|
| `mod.rs` | Attachment format constants; `impl_ldp_vc_details_format!` macro |
| `credential.rs` | `Credential` — final issued VC message with `please_ack` support |
| `credential_offer.rs` | `CredentialOffer` — issuer's offer with credential preview and VC attachment |
| `credential_preview.rs` | `CredentialPreviewData` / `CredentialValue` — human-readable attribute preview |
| `credential_proposal.rs` | `CredentialProposal` — holder's suggestion of credential type |
| `credential_request.rs` | `CredentialRequest` — holder's formal request for the offered credential |

## Key types / traits
- `Credential`, `CredentialOffer`, `CredentialRequest`, `CredentialProposal` — main exchange messages
- `CredentialPreviewData` — embedded attribute preview in offers
- `impl_ldp_vc_details_format!` — generates `set_ldp_vc_credential` / `get_ldp_vc_credential` on message structs

## Dependencies
- Depends on: `crate::didcomm::core::envelope`, `crate::vc::formats::json_ld_vc`, `crate::didcomm::protocol::aries::common`
- Used by: `issuance::holder`, `issuance::issuer`, `issuance::protocol`

## Constraints
- Attachment formats supported: `LINKED_DATA_PROOF_VC_DETAIL`, `HYPERLEDGER_INDY_*`
