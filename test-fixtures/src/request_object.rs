//! OID4VP signed Authorization Request Object (`typ: oauth-authz-req+jwt`).
//!
//! The SDK builds this inside `vc::oid4vp::verifier`, which exposes no
//! constructor, so the parameter set is assembled here and signed through the
//! verifier key's KMS handle. The `kid` header carries the verifier's
//! verification method URL and its DID must match `client_id` — the check the
//! SDK's holder makes first.

use serde_json::{Map, Value};

use crate::claims::{DEFAULT_NONCE, DEFAULT_VCT};
use crate::error::Result;
use crate::jws::sign_compact;
use crate::keys::FixtureKey;

/// The `typ` header OID4VP requires on a signed request object.
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// Builder for a signed OID4VP request object.
///
/// The defaults form a request the SDK's holder accepts: a `dc_api.jwt`
/// response mode (which needs no response URI and drives no HTTP on the error
/// path), a one-credential DCQL query and a nonce.
pub struct RequestObject<'a> {
    key: &'a FixtureKey,
    client_id: Option<String>,
}

impl<'a> RequestObject<'a> {
    /// Starts a request object signed by `key`.
    #[must_use]
    pub fn builder(key: &'a FixtureKey) -> Self {
        Self {
            key,
            client_id: None,
        }
    }

    /// Sets `client_id`. Defaults to `decentralized_identifier:<the key's DID>`,
    /// which is the form whose DID matches the `kid` header.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// The `client_id` this request will carry.
    #[must_use]
    pub fn resolved_client_id(&self) -> String {
        self.client_id
            .clone()
            .unwrap_or_else(|| format!("decentralized_identifier:{}", self.key.did))
    }

    /// Signs the request object and returns the compact JWT.
    ///
    /// # Errors
    ///
    /// See [`crate::jws::sign_compact`].
    pub async fn build(self) -> Result<String> {
        let client_id = self.resolved_client_id();

        let mut params = Map::new();
        params.insert("client_id".to_string(), Value::from(client_id));
        params.insert("response_type".to_string(), Value::from("vp_token"));
        params.insert("response_mode".to_string(), Value::from("dc_api.jwt"));
        params.insert("nonce".to_string(), Value::from(DEFAULT_NONCE));
        params.insert("aud".to_string(), Value::from("https://self-issued.me/v2"));
        params.insert(
            "dcql_query".to_string(),
            serde_json::json!({
                "credentials": [{
                    "id": "fixture-credential",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [DEFAULT_VCT] },
                    "claims": [{ "path": ["name"] }]
                }]
            }),
        );
        params.insert(
            "client_metadata".to_string(),
            serde_json::json!({ "vp_formats_supported": { "dc+sd-jwt": {} } }),
        );

        sign_compact(self.key, REQUEST_OBJECT_TYP, &Value::Object(params)).await
    }
}
