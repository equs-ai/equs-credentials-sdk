# inmem/crypto — Context

## Purpose
Provides concrete in-memory implementations of all cryptographic suites supported by EQUS SDK, implementing the `Suite`, `Signer`, `Verifier`, and `Key` traits defined in `crate::crypto`.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; declares sub-modules and the `HasAlg` helper trait. |
| `ecdsa.rs` | Generic `Ecdsa<C>` suite implementing `Suite`/`Signer`/`Verifier`/`Key` for any prime ECDSA curve; also defines `HasJWK` trait. |
| `ed25519.rs` | `Ed25519` suite: EdDSA signing and verification using `ed25519-dalek`. |
| `p256.rs` | `P256` type alias (`Ecdsa<NistP256>`) with P-256 JWK and ES256 algorithm binding. |
| `k256.rs` | `K256` type alias (`Ecdsa<Secp256k1>`) with secp256k1 JWK and ES256K algorithm binding. |
| `bls12381.rs` | `Bls12381` suite: BBS+ multi-message signing and verification over BLS12-381. |
| `bip32.rs` | `Bip32` helper: derives a `K256` signing key from a BIP-32 seed and derivation path. |

## Key types / traits
- `Ecdsa<C>` — generic ECDSA suite; concrete instances are `P256` and `K256`.
- `Ed25519` — EdDSA suite.
- `Bls12381` — BBS+ suite supporting `sign_multi` / `verify_multi`.
- `Bip32` — BIP-32 key derivation helper (not itself a `Suite`).
- `HasAlg` — associates a curve type with its EQUS SDK `Alg` value.
- `HasJWK` — associates a curve type with JWK serialization logic.

## Dependencies
- Depends on: `crate::crypto` (traits and error types), `ed25519-dalek`, `ecdsa`, `p256`, `bip32`, `ssi::bbs`, `zkryptium`
- Used by: `crate::inmem::kms` (`LocalKms` dispatches key operations to these suites)

## Constraints
- Available only under `#[cfg(any(test, feature = "in-memory"))]`.
