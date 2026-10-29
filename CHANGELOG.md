# Changelog

All notable changes to this project are documented here. The crate, the npm packages, the Android AAR
and the iOS XCFramework share one version.

## 1.2.0-rc.1

### Added

- `decline_authorization_request` takes an optional `DeclineAuthorizationRequest { error, description }`
  for the OpenID4VP error response: `error` is `AccessDenied` or `InvalidTransactionData`, `description`
  the `error_description`. Omitted, the response is unchanged: `access_denied` with "consent to share the
  presentation is not given".

### Changed

- **Breaking (Rust only):** `Holder::decline_authorization_request` takes a `reason` argument; pass `None`
  for the previous behaviour. Node.js, WASM, Kotlin and Swift take it as an optional trailing argument.
- A decline reason is rejected in `dc_api` and `dc_api.jwt` response modes, and a description that is
  empty or outside the RFC 6749 charset is rejected before sending.
- `MessageSender` authcrypts as `msg.from` when `SendOptions.from` is unset; it anoncrypts only when
  neither is set.
- `equs-didcomm` 0.1.1.

### Fixed

- A DIDComm message whose `from` is not its authenticated sender (authcrypt `skid` or signer `kid`) is
  rejected. Aries handlers reject a message without `from` or from anyone but the connection's peer.
- A DCQL response that answers one `credential_sets` option is accepted; it failed with
  `Requested presentation "…" not found`. The verifier checks every presented credential against its
  query and rejects a `vp_token` with an unknown query id, an empty presentation array, several
  presentations for a query without `multiple`, or a `transaction_data` item naming no presented
  credential.

## 1.1.1

### Security

- Dependency updates clearing advisories: `rustls-webpki`, `webpki-roots`, `webpki-root-certs`,
  `ctutils`, and `zip` 9 via `equs-one-core` 0.1.2.

## 1.1.0

No API changes.

### Changed

- GitHub releases also attach the `.crate` and the npm tarballs.
- `-rc.N` versions publish to npm under the `rc` dist-tag and are GitHub prereleases.
