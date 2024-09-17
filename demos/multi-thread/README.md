# SDK Demo - Multi-thread support for the APIs

This Demo demonstrates that Issuer API can handle multiple Holders.
Authorization, session management and nonce generation are explicitly skipped in this demo, to simplify the flow.

### Steps to run the demo

1. Run a trivial `actix_web` server with `Issuer`:
    ```bash
    cargo run issuer
    ```
2. Open a new terminal window and simultaneously run multiple `Holder`s:
    ```bash
    # Set Level to ERROR to avoid noisy outputs  
    RUST_LOG=ERROR cargo run holders <runs (default: 100)>
    ```

3. Check the output and logs

In case of failures command will print out number of failed requests and its percentage.