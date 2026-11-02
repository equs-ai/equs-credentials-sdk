# issuer — Context

## Purpose
Implements the credential issuer side of the WACI Aries issuance protocol: creating credential offers, producing OOB invitation URLs, handling credential requests, signing credentials with the KMS, and managing issuance state via an FSM.

## Files

| File | Role |
|------|------|
| `mod.rs` | `Issuer` — public API; `IssuerMessages` enum; `CredentialInfo` (with `credential_for`, the offered credential for a request's subject); `MessageHandler` impl |
| `issuer_fsm.rs` | `IssuerSM` — pure FSM driving `Initial → OfferSent → RequestReceived → CredentialSent → Finished`; a request that does not match the offer goes `OfferSent → Finished` |
| `states.rs` | `IssuerState` enum and five concrete state structs with `From` transition impls |
| `fixture.rs` | Test-only helper that builds a `CredentialInfo` with sample PermanentResident claims |

## Key types / traits
- `Issuer<KMS, KH, C, S>` — stateful issuer; generic over KMS, connection service, and storage
- `IssuerSM<KMS, KH, C>` — drives state transitions; handles proposal (unsupported, returns problem report)
- `IssuerState` — `Initial`, `OfferSent`, `RequestReceived`, `CredentialSent`, `Finished`
- `CredentialInfo` — bundles VC metadata, claims, and KMS key reference for signing

## Dependencies
- Depends on: `issuance::message`, `issuance::protocol::IssuanceProtocol`, `outofband::OutOfBandV2Protocol`, `crate::kms`, `crate::vc::formats::json_ld_vc::JsonLdAPI`
- Used by: `issuance::protocol::IssuanceProtocol::new_with_issuer`

## Constraints
- The issuer signs only what it offered. A `request-credential` is accepted only when its credential equals `CredentialInfo`'s, apart from the first credential subject's `id`, which must be a string. Any other request sends an `invalid-credential-request` problem report and finishes the exchange as `Failed`, unsigned.
- `send_credential` signs `CredentialInfo`'s credential with the request's subject `id`, never the requested credential itself; a signing failure is returned as `Error::VC`.
