# problem_report — Context

## Purpose
Implements the Aries `report-problem/2.0` protocol, providing structured error messages that any participant in an issuance or presentation exchange can send to signal failures or rejections.

## Files

| File | Role |
|------|------|
| `mod.rs` | Protocol constants (`report-problem/2.0`, `PROBLEM_REPORT` type name) |
| `message.rs` | `ProblemReport`, `ProblemReportBody`, `ProblemReportCode`, `Reason` |
| `protocol.rs` | `ProblemReportProtocol` — `Protocol` impl delegating to an injected `MessageHandler` |

## Key types / traits
- `ProblemReport` — structured error message with code, comment, and args
- `ProblemReportCode` — well-known error codes (unimplemented, invalid offer/request/credential, rejected, etc.)
- `Reason` (Fail/Reject) — maps a `ProblemReport` to a `Status` variant

## Dependencies
- Depends on: `crate::didcomm::protocol::aries::common::message::{Status, Thread}`, `crate::didcomm::core::envelope`
- Used by: `issuance::holder`, `issuance::issuer`, `present_proof::holder`, `present_proof::verifier`
