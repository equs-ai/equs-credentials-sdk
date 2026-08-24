# demos — Context

## Purpose
Standalone demonstration applications showing Equs SDK usage across multiple target environments
(pure Rust, Node.js, WASM, Android, iOS) and use cases (OID4VC flows, multi-threading).

## Files / Sub-areas

| File/Dir     | Role |
|--------------|------|
| README.md    | Top-level index linking to each demo's README. |
| oid4vc/      | Pure-Rust OID4VCI + OID4VP demo with Actix-web issuer, verifier, and holder services. See [oid4vc/CLAUDE.md](oid4vc/CLAUDE.md). |
| nodejs/      | Node.js (TypeScript) OID4VC demo using Equs SDK's NAPI-RS bindings. See [nodejs/CLAUDE.md](nodejs/CLAUDE.md). |
| wasm/        | Browser/WASM OID4VC wallet demo using Equs SDK's WASM bindings. See [wasm/CLAUDE.md](wasm/CLAUDE.md). |
| multi-thread/| Rust concurrency demo; proves `IssuerService` is thread-safe under concurrent holder load. See [multi-thread/CLAUDE.md](multi-thread/CLAUDE.md). |
| android/     | Android Kotlin demo using Equs SDK's UniFFI wrapper (AAR). See [android/CLAUDE.md](android/CLAUDE.md). |
| ios/         | iOS Swift demo using Equs SDK's UniFFI wrapper (XCFramework). See [ios/CLAUDE.md](ios/CLAUDE.md). |
| keycloak/    | Docker Compose setup providing the OAuth2/OIDC authorization server for OID4VC demos. See [keycloak/CLAUDE.md](keycloak/CLAUDE.md). |

## Key types / traits (if applicable)
- All demos are consumers of Equs SDK; they do not define new SDK types.

## Dependencies
- Depends on: `equs_sdk` and its wrappers (`wrappers/nodejs/`, `wrappers/wasm/`, `wrappers/uniffi/`), Keycloak (external), Node.js/npm, Xcode (iOS), Android SDK/Gradle
- Used by: developers exploring Equs SDK capabilities and integration patterns

## Constraints
- Most OID4VC demos require Keycloak running locally via `demos/keycloak/docker-compose.yaml`.
- Mobile demos (Android, iOS) require platform-specific toolchains and pre-built wrapper binaries.
- Demo `.rs` source files are not part of the main Equs SDK library and should not be modified as part of SDK development.
