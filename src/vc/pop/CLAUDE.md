# pop — Context

## Purpose
Defines the Proof of Possession abstraction and provides a JWT-based implementation used during OID4VCI credential requests.

## Files

| File | Role |
|------|------|
| mod.rs | `ProofOfPossession` trait, `Format` enum (Jwt / DiVp), `GenerateOptions`, `VerifyOptions`, and the shared `Error` type. |
| jwt_pop.rs | `JwtProofOfPossession` — JWT PoP signed with the holder key and verified via DID-document resolution. |

## Key types / traits
- `ProofOfPossession<P>` — async trait: `generate`, `verify`, `alg`.
- `Format` — serialization format of the proof (`Jwt`, `DiVp`).
- `GenerateOptions` / `VerifyOptions` — configure audience, issuer, lifetime, nonce, clock tolerance.

## Dependencies
- Depends on: `oid4vci::proof_of_possession`, `ssi::claims::jws`, `crate::crypto`, `crate::did::universal::UniversalResolver`
- Used by: `core::IssuerService` (verification), `core::HolderService` (generation), `oid4vci::holder`
