# wasm — Context

## Purpose
Browser/WASM demonstration of the OID4VCI and OID4VP end-to-end flow using the ASDK WASM
bindings, showing SDK consumption from a frontend web application.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| oid4vc/  | Vite-based frontend application (TypeScript) implementing the holder wallet in a browser using ASDK's WASM target; see [oid4vc/README.md](oid4vc/README.md) for setup and usage. |

## Dependencies
- Depends on: ASDK WASM bindings (compiled from `wrappers/wasm/`), Node.js, npm, Keycloak
- Used by: developers evaluating ASDK wallet functionality in a browser context

## Constraints
- Requires a running Keycloak instance with CORS configured for the frontend origin.
- The ASDK WASM package must be built before running `npm i`.
