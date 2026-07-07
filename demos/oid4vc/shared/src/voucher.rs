//! Shared voucher identifiers and the DCQL query used by both the Merchant
//! (Verifier) and the Agent (Delegate Holder) so they agree on the request shape.

use agent_sdk::vc::dcql::{DCQL, DCQLCredential, NonEmptyVec};
use serde_json::json;
use uuid::Uuid;

/// The voucher credential type (vct) the Bank issues.
pub const VOUCHER_VCT: &str = "https://bank.example/voucher";
/// DCQL credential id used in the Merchant's voucher query.
pub const VOUCHER_DCQL_ID: &str = "voucher";

/// Mint a fresh purchase identifier. The Merchant calls this once per checkout
/// when it creates the authorization request; the value then flows to the Agent
/// (via the DCQL) and into the delegate payload.
pub fn generate_purchase_id() -> String {
    format!("P-{}", Uuid::new_v4())
}

/// The Merchant's voucher query: a `dc+sd-jwt` voucher whose `purchase_id`
/// claim equals `purchase_id`, also disclosing `amount` and `currency`.
///
/// Field names (`meta.vct_values`, claim `values`, `claim_sets`) match the
/// `DCQLCredential` shape in `agent_sdk::vc::dcql` (see `src/vc/dcql/mod.rs`).
pub fn voucher_dcql(purchase_id: &str) -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!({
        "id": VOUCHER_DCQL_ID,
        "format": "dc+sd-jwt",
        "meta": { "vct_values": [VOUCHER_VCT] },
        "claims": [
            { "id": "pid", "path": ["purchase_id"], "values": [purchase_id] },
            { "id": "amt", "path": ["amount"] },
            { "id": "cur", "path": ["currency"] }
        ],
        "claim_sets": [["pid", "amt", "cur"]]
    }))
    .expect("voucher DCQL credential is valid");

    DCQL::new(NonEmptyVec::new(desc))
}

/// Read the required `purchase_id` value back out of a voucher DCQL — the Agent
/// uses this to learn the Merchant's generated purchase id from AR1.
pub fn purchase_id_from_dcql(dcql: &DCQL) -> Option<String> {
    let v = serde_json::to_value(dcql).ok()?;
    let claims = v["credentials"][0]["claims"].as_array()?;
    let pid = claims
        .iter()
        .find(|c| c["path"][0] == json!("purchase_id"))?;
    pid["values"][0].as_str().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn voucher_dcql_constrains_vct_and_purchase_id() {
        let purchase_id = generate_purchase_id();
        let dcql = voucher_dcql(&purchase_id);
        let v: Value = serde_json::to_value(&dcql).expect("DCQL serializes");
        let cred = &v["credentials"][0];
        assert_eq!(cred["id"], Value::String(VOUCHER_DCQL_ID.to_string()));
        assert_eq!(cred["format"], Value::String("dc+sd-jwt".to_string()));
        // vct is constrained to the voucher type.
        assert_eq!(
            cred["meta"]["vct_values"][0],
            Value::String(VOUCHER_VCT.to_string())
        );
        // A claim requires purchase_id == the generated value.
        let claims = cred["claims"].as_array().expect("claims array");
        let pid = claims
            .iter()
            .find(|c| c["path"][0] == Value::String("purchase_id".to_string()))
            .expect("purchase_id claim present");
        assert_eq!(pid["values"][0], Value::String(purchase_id.clone()));
    }

    #[test]
    fn generate_purchase_id_is_unique_and_roundtrips_through_dcql() {
        let a = generate_purchase_id();
        let b = generate_purchase_id();
        assert_ne!(a, b, "each checkout mints a distinct purchase_id");
        assert!(a.starts_with("P-"));
        // The Agent can read the Merchant's generated value back out of the query.
        assert_eq!(purchase_id_from_dcql(&voucher_dcql(&a)), Some(a));
    }
}
