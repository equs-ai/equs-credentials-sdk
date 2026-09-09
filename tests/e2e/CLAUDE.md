# e2e — Context

## Purpose
End-to-end integration tests validating complete protocol flows through EQUS SDK's public API surface,
from credential issuance to presentation and verification using in-memory and real HTTP transports.

## Files / Sub-areas

| File/Dir              | Role |
|-----------------------|------|
| mod.rs                | Declares all e2e sub-modules. |
| vc_core.rs            | Tests the `vc::core` (`IssuerService` / `HolderService` / `VerifierService`) API: SD-JWT issuance + presentation, BBS+ selective-disclosure presentation, and credential status list verification. |
| vc_oid4vci.rs         | Tests the OID4VCI protocol end-to-end (authorization-code flow with scope); exercises SD-JWT and JSON-LD credential issuance, optional token introspection, and extra credential verification. |
| vc_oid4vp.rs          | Tests the OID4VP presentation flow; covers Presentation Exchange (JSON-LD, single/multiple SD-JWT), DCQL queries, and mDL VP token verification with trusted and untrusted IACA certificates. |
| waci_aries.rs         | Tests the WACI/Aries DIDComm protocols: multi-step credential issuance and proof-presentation state machines using real HTTP transport between two in-process agents. |
| protocol_engine.rs    | Tests the DIDComm protocol engine: OOB invitation, connection establishment, and full TicTacToe FSM state transitions between two HTTP-transport agents. |
| custom_did_resolvers.rs | Tests that custom `DIDResolver` implementations (via `TestDIDResolver` / `did:test`) integrate cleanly with the OID4VCI and OID4VP issuer/holder/verifier builders. |

## Key types / traits (if applicable)
- Uses `LocalKms`, `InMemVault`, `HttpClientEmulator`, `UniversalResolver`, `TestDIDResolver`.
- Uses `IssuerService`, `HolderService`, `VerifierService` (vc::core) and OID4VCI/OID4VP builder patterns.

## Dependencies
- Depends on: `equs_sdk`, `tests/utils/` (all sub-modules), `rstest`, `mockito`, `serde_json`, `url`, `time`
- Used by: CI test runner via `cargo test --features in-memory,didcomm-http-transport`

## Constraints
- Tests require the `in-memory` and `didcomm-http-transport` features.
- WACI/Aries and protocol-engine tests bind to loopback ports and must not run in parallel with conflicting port assignments.
