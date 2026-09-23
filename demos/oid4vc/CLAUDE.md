# oid4vc — Context

## Purpose
Pure-Rust demonstration of the full OID4VCI and OID4VP end-to-end flow, implemented as three
separate Actix-web services (issuer, verifier, holder) plus shared library code.

## Files / Sub-areas

| File/Dir  | Role |
|-----------|------|
| issuer/   | Actix-web HTTP server implementing the OID4VCI credential issuer; integrates with Keycloak for OAuth2 authorization. |
| verifier/ | Actix-web HTTP server implementing the OID4VP verifier; creates authorization requests and verifies presentations. |
| holder/   | CLI-driven holder application; discovers issuer metadata, performs authorization-code flow, requests credentials, and presents them to the verifier. |
| agent/    | Actix-web Delegate Holder (Agent) service for the dSD-JWT delegation demo; acts as verifier toward the holder and as wallet toward the verifier. Binds `:8108`. |
| shared/   | Common types, configuration, and utilities shared across the services (incl. `voucher` DCQL helpers). |
| demo.sh   | Shell script that orchestrates the full demo startup sequence. |
| delegation-demo.sh | Shell script for the dSD-JWT delegation demo: launches issuer/verifier/agent and prints a runbook for the interactive Holder. |
| README.md | Step-by-step run instructions, verifier environment variables, and the dSD-JWT delegation demo. |

## Dependencies
- Depends on: `equs_sdk` (vc::oid4vci, vc::oid4vp), Keycloak (external, for OAuth2)
- Used by: developers evaluating EQUS Credentials SDK OID4VC flows in a native Rust environment

## Constraints
- Requires a running Keycloak instance; see `demos/keycloak/README.md` for setup.
- Services bind to specific ports; see `shared/` configuration for defaults.
