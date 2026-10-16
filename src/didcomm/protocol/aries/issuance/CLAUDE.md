# issuance — Context

## Purpose
Full implementation of the WACI Aries `issue-credential/3.0` DIDComm protocol, covering both the issuer and holder roles including OOB invitation flows, credential signing, vault storage, and error reporting.

## Files

| File | Role |
|------|------|
| `mod.rs` | `Error` enum, `Result` alias, and protocol-name/version constants |
| `protocol.rs` | `IssuanceProtocol` — `Protocol` impl, constructed with either issuer or holder handler |
| `holder/` | `IssuanceHolder`, holder FSM, holder states |
| `issuer/` | `Issuer`, issuer FSM, issuer states, test fixture |
| `message/` | Wire-format message structs and attachment macros |

## Key types / traits
- `IssuanceProtocol` — registered with `Agent`; routes incoming messages to the right handler
- `Issuer` / `IssuanceHolder` — stateful role objects (implement `MessageHandler`)
- `Error` — comprehensive error enum covering KMS, storage, vault, OOB, parse, and VC errors

## Dependencies
- Depends on: `crate::kms`, `crate::vault`, `crate::storage`, `crate::vc`, `outofband`, `problem_report`, `empty`, `crate::didcomm::agent`
- Used by: application code that creates `Issuer::new` or `IssuanceHolder::new`

## Constraints
- Non-wasm only
