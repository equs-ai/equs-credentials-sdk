# didcomm::core::envelope — Context

## Purpose
Wraps the external `didcomm` crate to provide DIDComm V2 message packing and unpacking. Adapts EQUS SDK's `UniversalResolver` and `Kms` types to the interfaces expected by the `didcomm` crate.

## Files

| File | Role |
|------|------|
| `mod.rs` | `EnvelopeService`, type aliases, `DIDCommKms` re-export, `Error`/`Result`, tests |
| `kms.rs` | `KmsWrapper<KMS, KH>` — adapts `Kms<KH>` to `didcomm::secrets::KeyManagementService` |
| `did_resolver.rs` | `DidResolverWrapper` — adapts `UniversalResolver` to `didcomm::did::DIDResolver` |

## Key types / traits

### `EnvelopeService`
```
new<KMS, KH>(kms: KMS, did_resolver: UniversalResolver) → Self
pack_plaintext(message) → Result<String>
pack_signed(message, sign_by) → Result<(String, PackSignedMetadata)>
pack_encrypted(message, to, from, sign_by, options) → Result<(String, PackEncryptedMetadata)>
unpack(msg, options) → Result<(Message, UnpackMetadata)>
```

### Type aliases (all from `didcomm::*`, re-exported publicly)
`Message`, `MessageBuilder`, `Attachment`, `AttachmentBuilder`, `AttachmentData`,
`PackEncryptedOptions`, `PackEncryptedMetadata`, `PackSignedMetadata`,
`UnpackOptions`, `UnpackMetadata`, `AuthCryptAlg`.

### `DIDCommKms` (re-exported)
Supertrait: EQUS SDK's `Kms<KH>` combined with `didcomm` crate's `KeyManagementService` adapter. Required by `Agent::new`.

## Error type
Single-variant snafu struct: `Error { source: didcomm::error::Error, location: Location }`.

## Tests (in `mod.rs`)
- `pack_encrypted_succeeded` — round-trips encrypted auth message between two `did:peer:4` DIDs.
- `pack_signed_succeeded` — round-trips a signed message.
- `pack_plaintext_succeeded` — verifies exact JSON output of plaintext pack.
- Two `#[should_panic]` tests: incorrect sender DID and incorrect recipient DID.

All tests use `LocalKms` + `UniversalResolver::default()` + `DIDPeer::generate_did_peer4`.

## Dependencies
- Depends on: `didcomm` crate, `crate::did::UniversalResolver`, `crate::kms::Kms`, `crate::inmem::LocalKms` (tests only)
- Used by: `crate::didcomm::core::{MessageReceiver, MessageSender}`, `crate::didcomm::agent::Agent`

## Constraints
- Non-wasm only.
