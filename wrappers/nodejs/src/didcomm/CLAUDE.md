# didcomm — Context

## Purpose
Exposes the DIDComm V2 envelope service to Node.js via NAPI-RS. Provides NAPI types for a callback-based KMS (`DIDCommKms`) that satisfies both `Kms` and `DerivativeKms` traits, and a `JsDIDCommService` that wraps `EnvelopeService` to pack and unpack plaintext, signed, and encrypted DIDComm messages.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `kms` and `service` submodules. |
| `kms.rs` | `DIDCommKms` — NAPI object (callback-based) implementing `Kms<JsKeyHandle>`, `DerivativeKms<ECDH1PUParams>`, and `DerivativeKms<ECDHESParams>`. Bridges JS promise callbacks for key creation, retrieval, and ECDH derivations. |
| `service.rs` | `JsDIDCommService` — NAPI class wrapping `EnvelopeService`. Exposes `pack_plaintext`, `pack_signed`, `pack_encrypted`, and `unpack` as async NAPI methods. Constructs the service with a `DIDCommKms` and a default `UniversalResolver`. |

## Key types / traits
- `DIDCommKms` — JS-callback-driven KMS satisfying the DIDComm engine's `Kms` and `DerivativeKms` requirements.
- `JsDIDCommService` — NAPI class for full DIDComm V2 pack/unpack operations.
- `PackEncryptedResult`, `PackSignedResult`, `UnpackResult` — NAPI result objects returned from the service methods.

## Dependencies
- Depends on: `equs_sdk::didcomm::core::envelope` (`EnvelopeService`, `PackEncryptedOptions`, `UnpackOptions`), `equs_sdk::kms`, `crate::kms::JsKeyHandle`
- Used by: Node.js consumers of the SDK that implement DIDComm messaging

## Constraints
- `EnvelopeService` and DIDComm are non-wasm only in the core library; this module is therefore only compiled for the Node.js target.
