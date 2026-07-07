# oid4vc/agent/src — Context

## Purpose
Runnable demo binary implementing the **Delegate Holder (Agent)** role in the dSD-JWT
delegation flow. The Agent is simultaneously an OID4VP **Verifier toward the Holder**
(it requests delegation of the voucher) and an OID4VP **Wallet toward the Merchant**
(it presents the delegated voucher with its own KB-JWT).

## Files

| File | Role |
|------|------|
| `main.rs` | Entry point: wires `LocalKms` (verifier key + a separate Agent `cnf`/KB key), `ReqwestClient`, an OID4VP `Verifier`, a shared `InMemVault`, and (per request) an OID4VP `Holder` wallet. Endpoints: `POST /checkout` (fetch Merchant AR1, extract `purchase_id`, return the AR2 request URI to paste into the Holder CLI), `GET /request_uri`, `GET /request`, `POST /present` (verify+capture the grant, store it in the Agent's vault, then present it to the Merchant via `present_credentials_auto` with the Agent's own KB-JWT). |

## Key types / traits
- Uses `vc::oid4vp::Verifier`, `Holder`, `DelegationRequest`, `delegate_transaction_data_item`,
  `DelegateSdJwtTransactionDataFormat` from `agent_sdk` (feature `delegate-sd-jwt`).
- Uses `vault::Vault` (`store_credential`) and `vc::{CredentialMetadata, VCFormat}` to persist
  the captured grant into the Agent's wallet vault.
- Uses `shared::voucher` (`VOUCHER_VCT`, `VOUCHER_DCQL_ID`, `generate_purchase_id`, `purchase_id_from_dcql`).
- Stores the captured grant in a shared `InMemVault` (bound to the Agent's `cnf`/KB key,
  `agent_key_metadata.kid`) and presents it via `present_credentials_auto` — the wallet
  discovers the grant from the vault by the Merchant DCQL's claim-path `fields`. No explicit
  `CredentialMapping` is used.
- `AppState` — holds the verifier, the Agent's `cnf` JWK + key metadata + KMS, the
  current `purchase_id`, the Agent's wallet vault (`agent_vault`), and
  request/session/transaction-data storages.

## Dependencies
- Depends on: `agent_sdk` (oid4vp, dcql, kms, inmem, reqwest, crypto, vc::core; features
  `in-memory`, `delegate-sd-jwt`), `shared` (sibling lib crate), `actix-web`, `reqwest`.
- Used by: developers demonstrating the delegated SD-JWT (dSD-JWT) flow end-to-end.

## Constraints
- Demo / development use only; binds to `http://localhost:8108`.
- The Agent verifies the received grant with `transaction_data: None` (a delegate grant
  returns no transaction-data hashes; authenticity comes from the chain signature and the
  `aud`/`nonce`/`purchase_id` bound into the delegate payload).
