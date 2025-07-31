# SDK Demo - OID4VC Service
This Demo allows to demonstrate the end-to-end flow of the OID4VCI/VP protocol.
The Web server in the root represents the Issuer and Verifier sides and the holder folder contains the Holder side.

### Setup keycloak by [instructions](../keycloak/README.md)

### Steps to run the demo

1. Run issuer server:
    ```bash
    cargo run --manifest-path ./issuer/Cargo.toml
    ```
2. Open a new terminal window. Run verifier server:
    ```bash
    cargo run --manifest-path ./verifier/Cargo.toml
    ```
3. Open a new terminal window. Run demo:
    ```bash
    cargo run --manifest-path ./holder/Cargo.toml
    ```
4. Follow the instructions on the console.