# keycloak — Context

## Purpose
Docker Compose setup for running a pre-configured Keycloak instance that acts as the OAuth2/OIDC
authorization server required by the OID4VC demo services.

## Files / Sub-areas

| File/Dir            | Role |
|---------------------|------|
| docker-compose.yaml | Defines the Keycloak service with realm import and theme mounting. |
| realms/             | Pre-configured realm JSON exports (e.g., `pid-issuer-realm`) with clients and scopes for demo flows. |
| themes/             | Custom Keycloak UI themes used by the demo realm. |
| certs/              | TLS certificates for HTTPS if needed. |
| extra/              | Additional Keycloak configuration files. |

## Dependencies
- Depends on: Docker / Docker Compose, Keycloak (official image)
- Used by: all demo applications that require OAuth2 authorization (`oid4vc`, `nodejs`, `wasm`, `android`, `ios`)

## Constraints
- Must be started before running any OID4VC demo; see the README linked from the parent demos/README.md.
- For the WASM demo, the Keycloak client's allowed origins must include the frontend host to avoid CORS issues.
