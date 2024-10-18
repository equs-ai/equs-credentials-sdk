# SDK Demo - OID4VC Service
This Demo allows to demonstrate the end-to-end flow of the OID4VCI/VP protocol.
The Web server in the root represents the Issuer and Verifier sides and the holder folder contains the Holder side.

### Setup keycloak by [instructions](../keycloak/README.md)

### Steps to run the demo

1. Run an issuer server:
    ```bash
    cd issuer
    cargo run
    ```
2. Open a new terminal window. Go to the `verifier` folder and run a web server:
    ```bash
    cd verifier
    cargo run
    ```
3. Open a new terminal window. Go to the `holder` folder and run demo
    ```bash
    cd  holder
    cargo run
    ```
4. Follow the instructions on the console.