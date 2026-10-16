# types — Context

## Purpose
Defines all domain types used by the `did:ethr` resolver: Ethereum addresses, block references, on-chain event structs, DID document attribute representations, the DID document builder, and resolution output types. These types are consumed exclusively within `didethr/` and are not exposed at the crate root.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports the public surface of all sub-modules under a flat `types::` namespace. |
| `address.rs` | `Address` — newtype wrapping an Ethereum address string; normalizes `0x` prefix; produces EIP-155 blockchain account IDs. |
| `block.rs` | `Block` — newtype wrapping a `u64` block number; `BlockDetails` — pairs a block number with its timestamp. |
| `did_doc_attribute.rs` | `DidDocAttribute`, `PublicKeyAttribute`, `ServiceAttribute` — attribute payloads decoded from `DIDAttributeChanged` events; enums `VerificationKeyType`, `PublicKeyType`, `PublicKeyPurpose`, `DelegateType`. |
| `did_doc_builder.rs` | `DidDocumentBuilder` — stateful builder that accumulates verification methods, relationship references, and services from event history and serializes them into an `ssi::dids::Document`. |
| `did_events.rs` | `DidEvents` enum and concrete event structs (`DidAttributeChanged`, `DidDelegateChanged`, `DidOwnerChanged`) decoded from Ethereum log data. |
| `resolution.rs` | Resolution I/O types: `DidRecord`, `DidDocumentWithMeta`, `DidMetadata`, `DidResolutionMetadata`, `DidResolutionOptions`, `DidResolutionError`; also the `DID_RESOLUTION_FORMAT` constant. |

## Key types / traits
- `Address` — normalized Ethereum address; converts from raw hex strings or `did:ethr:…` DIDs.
- `Block` — block-number newtype; `is_none()` signals the zero / "never changed" sentinel.
- `BlockDetails` — block number + UNIX timestamp returned by `eth_getBlockByNumber`.
- `DidEvents` — enum over the three EtherDIDRegistry event kinds; carries a `previous_change` pointer for linked-list traversal.
- `DidDocAttribute` — parsed attribute payload (public key or service) derived from a `DIDAttributeChanged` event.
- `VerificationKeyType` — full set of W3C verification-method types supported by `did:ethr`.
- `DelegateType` — `VeriKey` (assertion) / `SigAuth` (authentication) delegate roles.
- `PublicKeyPurpose` — purpose tag (`veriKey`, `sigAuth`, `enc`) for attribute-based keys.
- `DidDocumentBuilder` — builder for `ssi::dids::Document`; tracks verification methods and relationship references by string key to support add/remove semantics during event replay.
- `DidRecord` — pairs a resolved `Document` with its `DidMetadata`.
- `DID_RESOLUTION_FORMAT` — MIME type constant `"application/did+ld+json"`.

## Dependencies
- Depends on: `ssi` crate (`Document`, `DIDBuf`, `DIDURLBuf`, `DIDVerificationMethod`), `iref` (`IriBuf`), `serde`, `base64`, `bs58`, `hex`, `crate::did::ResolutionError`, `crate::did::didethr::utils`
- Used by: `crate::did::didethr::client` (event structs, `Address`, `Block`), `crate::did::didethr::registry` (block and event types), and the resolver logic in the parent `client.rs`

## Constraints
- No wasm gate — this module contains pure data types with no I/O and is compiled for all targets.
