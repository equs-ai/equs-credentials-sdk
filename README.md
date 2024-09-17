# Agent SDK (ASDK)
- [About ASDK](#about-asdk)
- [API and Components](#api-and-components)
- [Supported SSI Standards](#supported-ssi-standards)
- [How To Build and Run](#how-to-build-and-run)
- [How to Use ASDK in Applications](#how-to-use-asdk-in-applications)
- [Dependencies](#dependencies)
- [Development Guidelines](docs/guidlines/dev.md)

## About ASDK
- ASDK is an SDK (library) providing building blocks for Self-Sovereign Identity (SSI) use cases.  
- ASDK is written in Rust; language wrappers will be added later (see Roadmap below).  
- ASDK is not an end-user application, but just an ASDK. Applications integrating ASDK will need to implement some interfaces (such as KMS and Vault) or Web endpoints (OID4VC). See [How To Use ASDK](#how-to-use-asdk-in-applications) below.
- ASDK supports multiple SSI protocols and specifications (see below). 

![asdk](docs/asdk.png)

Other diagrams:
- [API Tiers](docs/api-tiers.png)
- [Components](docs/asdk-components.png)
- [VC OID4VC API Auth Code: Full Flow](docs/vc-oid4vc-api-auth-code-full.png)
- [VC OID4VC API Auth Code: Already Authorized](docs/vc-oid4vc-api-auth-code-already-authorized.png)
- [VC Core API](docs/vc-core-api.png)

## API and Components
![asdk-tiers](docs/api-tiers.png)
![asdk-components](docs/asdk-components.png)

## Supported SSI Standards
See [Components](docs/asdk-components.png).
#### Implemented
- VC Formats:
  - SD-JWT VC (version: TBD)
- VC Exchange Protocols:
    - OID4VCI (draft 14)
        - Authorization Code Flow using scope Parameter to Request Issuance of a Credential
    - OID4VP (draft 21)
        - Cross Device Flow
- DID methods
  - did:key (version: TBD)

#### Planned
- VC Formats:
    - W3C JSON-LD + BBS+
    - W3C JWT
    - Hyperledger AnonCreds
- VC Exchange Protocols:
    - OID4VCI
      - Pre-authorized Code Flow 
      - Authorization Code Flow Using Authorization Details Parameter
    - OID4VP
      - Same Device Flow
      - Response Mode "direct_post.jwt"
    - Aries AIPv2
- DID methods
    - did:web
    - did:peer
    - did:ethr or similar
- DIDComm and Protocols Engine 

## How To Build and Run
Pre-requisites:
- rustc version >=1.79

```
cargo build --all-features
cargo test --all-features
```

### Collecting logs on the application side
On the application side, to collect logs from `agent-sdk`, follow the steps below:

1. Add `tracing-subscriber` dependency into `Cargo.toml`:
  ```toml
    tracing-subscriber = "0.3.18"
  ```
2. Add the following to your executable to initialize the default subscriber:
```rust
use tracing_subscriber;

async fn main() {
    tracing_subscriber::fmt::init();
}
```
3. For example, to see `TRACE` level logs, run:
```shell
RUST_LOG=TRACE cargo run
```

### Generate documentation

```
cargo doc --no-deps
```

### Demos

- [OID4VC web service](demos/oid4vc/README.md)
- [Multi-thread support](demos/multi-thread/README.md)

## How to Use ASDK in Applications

### OID4VC
An example of integration: https://git.slock.it/equstng/proof-of-concepts/asdk-demo-oid4vc-service

![asdk-integration](docs/asdk-apps-integration.png)


**Mobile App (Holder)**
1. Implement application/platform specific KMS
2. Implement application/platform specific Vault (to store and find Verifiable Credentials)
3. Integrate OID4VC Holder API
   - [VC OID4VC API Auth Code: Full Flow](docs/vc-oid4vc-api-auth-code-full.png) or  [VC OID4VC API Auth Code: Already Authorized](docs/vc-oid4vc-api-auth-code-already-authorized.png)
   - For VCI refer to:
     - [Holder VCI API](src/vc/oid4vci/mod.rs)
     - [Holder VCI Builder](src/vc/oid4vci/builder.rs)
     - [Holder VCI Service](src/vc/oid4vci/holder.rs) (not publicly exposed)
   - For VP refer to:
     - [Holder VP API](src/vc/oid4vp/mod.rs)
     - [Holder VP Builder](src/vc/oid4vp/builder.rs)
     - [Holder VP Service](src/vc/oid4vp/holder.rs) (not publicly exposed)


**Web App: Issuer**
1. Implement application/platform specific KMS
2. Instantiate OID4VC Issuer Service
    - [VC OID4VC API Auth Code: Full Flow](docs/vc-oid4vc-api-auth-code-full.png) or  [VC OID4VC API Auth Code: Already Authorized](docs/vc-oid4vc-api-auth-code-already-authorized.png)
    - [Issuer API](src/vc/oid4vci/mod.rs)
    - [Issuer Builder](src/vc/oid4vci/builder.rs)
    - [Issuer Service](src/vc/oid4vci/issuer.rs) (not publicly exposed)
3. Create Issuer Metadata
4. Create Credential Offer (optional)
5. Implement the following endpoints. Each endpoint should call the corresponding ASDK Issuer API method.
    - GET /.well-known/openid-credential-issuer HTTP/1.1: `get_issuer_metadata`
    - POST /credential HTTP/1.1: `issue_credential`
6. Integrate Authorization Server (KeyCloak)
    - Either issue a new access token with the required scope (see [VC OID4VC API Auth Code: Full Flow](docs/vc-oid4vc-api-auth-code-full.png)), 
    - or re-use existing access token, but make sure that CredDefID is included as one of the scope values (see [VC OID4VC API Auth Code: Already Authorized](docs/vc-oid4vc-api-auth-code-already-authorized.png))


**Web App: Verifier**
1. Integrate OID4VC Verifier Service
   - [VC OID4VC API Auth Code](docs/vc-oid4vc-api-auth-code-full.png)
   - [Verifier API](src/vc/oid4vp/mod.rs)
   - [Verifier Builder](src/vc/oid4vp/builder.rs)
   - [Verifier Service](src/vc/oid4vp/verifier.rs) (not publicly exposed)
2. Implement the following endpoints. Each endpoint should call the corresponding ASDK Verifier API method.
   - POST /<authorization-response-uri> HTTP/1.1: `verify_presentation`



**Note:**
ASDK contains an example of KMS and Vault (not part of default build) based on [aries-askar](https://github.com/hyperledger/aries-askar), see [src/askar](src/askar). The current implementations are not recommended  for production (just demo purposes), but production ones can be created based on it.

## Dependencies
- https://github.com/spruceid/ssi (v0.7.0)
- https://github.com/openwallet-foundation-labs/sd-jwt-rust
- https://github.com/hyperledger/aries-askar (Test/Demo purposes, not part of default build)


