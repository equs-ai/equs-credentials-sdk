# nodejs — Context

## Purpose
Node.js demonstration of the OID4VCI and OID4VP end-to-end flow using the Equs SDK Node.js NAPI-RS
bindings, showing SDK consumption from a TypeScript/Node.js environment.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| oid4vc/  | TypeScript/Node.js application implementing issuer, verifier, and holder roles; see [oid4vc/README.md](oid4vc/README.md) for setup and usage. |

## Dependencies
- Depends on: Equs SDK Node.js NAPI-RS wrapper (compiled from `wrappers/nodejs/`), Node.js, npm, Keycloak
- Used by: developers evaluating Equs SDK from a Node.js / TypeScript environment

## Constraints
- Requires a running Keycloak instance; see `demos/keycloak/README.md`.
- The Equs SDK native module must be compiled before `npm run build`.
