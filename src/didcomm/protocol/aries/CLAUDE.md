# didcomm::protocol::aries — Context

## Purpose
Groups all Aries-compatible DIDComm protocol implementations. Each sub-module is an independent protocol family sharing common message utilities.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; declares and re-exports sub-modules |
| `common/` | Shared message structures: `Thread`, `Status`, general utilities — see [common/CLAUDE.md](common/CLAUDE.md) |
| `empty/` | Sentinel "empty" protocol; consumes ACK-like messages with no body — see [empty/CLAUDE.md](empty/CLAUDE.md) |
| `issuance/` | Aries Issue Credential v3 — `Issuer` and `IssuanceHolder` roles — see [issuance/CLAUDE.md](issuance/CLAUDE.md) |
| `present_proof/` | Aries Present Proof v3 — `Verifier` and `PresentationHolder` roles — see [present_proof/CLAUDE.md](present_proof/CLAUDE.md) |
| `problem_report/` | Problem Report message type and protocol handler — see [problem_report/CLAUDE.md](problem_report/CLAUDE.md) |

## Common patterns across Aries protocols
- Each protocol defines `PROTOCOL_NAME` and `PROTOCOL_VERSION` constants.
- Role structs are generic over `<KMS, KH, C, S>` (or subset).
- State is persisted to `Storage<String, StateEnum>` keyed by thread/request ID.
- `EventEmitter<String, StateEnum>` is embedded for subscriber notification of state transitions.
- `impl_didcomm_message_conversion!` macro generates `TryFrom<Message>` / `TryInto<Message>` for wire message structs.

## Dependency graph within Aries
`present_proof` and `issuance` both depend on:
- `aries::common` — `Thread`, `Status`
- `aries::problem_report` — `ProblemReport`, `PROBLEM_REPORT` constant
- `aries::empty` — `EMPTY` constant (for empty-body ACK handling)
- `protocol::outofband` — OOB invitation flows

## Dependencies
- Depends on: `crate::didcomm::agent`, `crate::didcomm::core`, `protocol::outofband`, `crate::vc::core`, `crate::kms`, `crate::storage`, `crate::vault`
- Used by: application code registering Aries protocols with `Agent`

## Constraints
- Non-wasm only.
