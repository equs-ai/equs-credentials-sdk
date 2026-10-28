# didcomm::core::envelope — Context

## Purpose
Wraps the external `didcomm` crate to provide DIDComm V2 message packing and unpacking. Adapts EQUS Credentials SDK's `UniversalResolver` and `Kms` types to the interfaces expected by the `didcomm` crate.

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
find_service_endpoint(did) → Result<Option<String>>
```
`find_service_endpoint` returns the URI of the DID's first `DIDCommMessaging` service that accepts `didcomm/v2` (or lists no `accept`), the same selection `pack_encrypted` applies when routing through a mediator.
`unpack` inherits the `didcomm` crate's (`equs-didcomm` ≥ 0.1.1) DIDComm v2.1 §Message Layer Addressing Consistency check: a set `message.from` must be the DID of `encrypted_from_kid` (authcrypt `skid`) and of `sign_from` (signer `kid`) whenever those are present; a mismatch is a `Malformed` error. A `from` with neither (plaintext, anoncrypt only) passes with `authenticated: false`.

### Type aliases (all from `didcomm::*`, re-exported publicly)
`Message`, `MessageBuilder`, `Attachment`, `AttachmentBuilder`, `AttachmentData`,
`PackEncryptedOptions`, `PackEncryptedMetadata`, `PackSignedMetadata`,
`UnpackOptions`, `UnpackMetadata`, `AuthCryptAlg`.

### `DIDCommKms` (re-exported)
Supertrait: the SDK's `Kms<KH>` combined with `didcomm` crate's `KeyManagementService` adapter. Required by `Agent::new`.

## Error type
Single-variant snafu struct: `Error { source: didcomm::error::Error, location: Location }`.

## Tests (in `mod.rs`)
- `pack_encrypted_succeeded` — round-trips encrypted auth message between two `did:peer:4` DIDs.
- `pack_signed_succeeded` — round-trips a signed message.
- `pack_plaintext_succeeded` — verifies exact JSON output of plaintext pack.
- Two `#[should_panic]` tests: incorrect sender DID and incorrect recipient DID.
- `unpack_failed_with_from_not_matching_signer` (`#[should_panic]`) — a JWS signed by one DID with `from` naming another; guards that the `didcomm` dependency enforces the sender binding.

All tests use `LocalKms` + `UniversalResolver::default()` + `DIDPeer::generate_did_peer4`.

## Dependencies
- Depends on: `didcomm` crate, `crate::did::UniversalResolver`, `crate::kms::Kms`, `crate::inmem::LocalKms` (tests only)
- Used by: `crate::didcomm::core::{MessageReceiver, MessageSender}`, `crate::didcomm::agent::Agent`

## Constraints
- Non-wasm only.
