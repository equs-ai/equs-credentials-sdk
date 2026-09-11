# SDK Demo - OID4VC Service

This demo demonstrates the end-to-end flow of the OID4VCI/OID4VP protocols.
The Web server in the root represents the Issuer and Verifier sides and the holder folder contains the Holder side.

### Set up Keycloak using these [instructions](../keycloak/README.md)

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

### Verifier configuration

Verifier accepts the following environment variables:

1. `TRANSACTION_DATA_DCQL_PATH` - path to a json file with transaction data (
   see [spec](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-2.8.1)) for DCQL
   authorization request. If not specified
   or incorrect, default transaction data will be used (see `default_transaction_data_for_dcql()`).
2. `TRANSACTION_DATA_PD_PATH` - path to a json file with transaction data (
   see [spec](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-2.8.1)) for Presentation
   Definition
   authorization request. If not specified
   or incorrect, default transaction data will be used (see `default_transaction_data_for_pd()`).

## Delegated SD-JWT (dSD-JWT) demo

Demonstrates a delegated credential flow with **five** entities:

- **End-User** — the human, operating the Holder CLI.
- **Issuer (Bank)** — issues a voucher credential (`vct = https://bank.example/voucher`).
- **Holder** — the End-User's wallet; holds the voucher and delegates it.
- **Delegate Holder (Agent)** — a new service (`:8108`) that is a *verifier* toward the
  Holder and a *wallet* toward the Merchant.
- **Verifier (Merchant)** — requests the voucher bound to a freshly generated `purchase_id`.

### Flow

1. The End-User's Holder obtains a voucher from the Bank.
2. The Agent starts a checkout at the Merchant and receives **Auth Request 1** (a voucher
   DCQL bound to a Merchant-generated `purchase_id`).
3. The Agent extracts that `purchase_id` and builds **Auth Request 2** — a `delegate`
   request carrying the Agent's `cnf` and the `purchase_id`.
4. The End-User pastes AR2 into the Holder CLI and approves; the Holder returns a dSD-JWT
   delegation grant bound to the Agent's key.
5. The Agent presents the grant to the Merchant with its **own KB-JWT** (Auth Response 1);
   the Merchant verifies the chain and value-matches `purchase_id`.

### Run it

A driver script launches the three services and prints a runbook. Keycloak is **not**
required (the issuer runs with `-F ci_demo`).

```bash
cd demos/oid4vc
./delegation-demo.sh
```

Then, in a separate terminal, run the Holder as the End-User and follow the printed steps:

```bash
cargo run --manifest-path ./holder/Cargo.toml -F delegate-sd-jwt
```

Notes:

- The `delegate-sd-jwt` Cargo feature makes the Holder additionally request the voucher
  during issuance (`-F delegate-sd-jwt` on the Holder) and makes the Merchant request the
  voucher (bound to a generated `purchase_id`) over `direct_post` (`-F delegate-sd-jwt` on
  the verifier, as `delegation-demo.sh` does). Without the feature, the existing demos
  build and behave unchanged. All three roles enable the feature: it forwards to the
  upstream SD-JWT chain support, which is what makes chain delegation (Holder), chain-aware
  discovery (Agent), and chain-aware verification (Merchant) available.
- The Agent crate lives in `agent/`; it builds Auth Request 2, captures the grant, stores it
  in its wallet vault, and presents it to the Merchant via `present_credentials_auto`. Auto
  discovery can value-match the delegate-injected `purchase_id` because, under
  `delegate-sd-jwt`, `Credential::parse_claims` layers each dSD-JWT chain link's delegate
  payload onto the issuer claims.
- The in-process logic (issue → delegate → present-with-KB → verify, with `purchase_id`
  binding) is covered by the `delegation_e2e_tests` in the SDK (`src/vc/oid4vp/tests.rs`),
  including `delegation_auto_discovery_value_matches_delegate_payload_claim`.
