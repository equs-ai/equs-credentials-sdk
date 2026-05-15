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
| shared/   | Common types, configuration, and utilities shared across the three services. |
| demo.sh   | Shell script that orchestrates the full demo startup sequence. |
| README.md | Step-by-step run instructions and verifier environment variable documentation. |

## Dependencies
- Depends on: `agent_sdk` (vc::oid4vci, vc::oid4vp), Keycloak (external, for OAuth2)
- Used by: developers evaluating ASDK OID4VC flows in a native Rust environment

## Constraints
- Requires a running Keycloak instance; see `demos/keycloak/README.md` for setup.
- Services bind to specific ports; see `shared/` configuration for defaults.
