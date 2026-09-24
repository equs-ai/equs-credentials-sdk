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
use crate::jws::{merge, sign_compact};
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
    nonce: String,
    response_type: String,
    response_mode: String,
    audience: String,
    state: Option<String>,
    dcql_query: Value,
    client_metadata: Value,
    overrides: Map<String, Value>,
}

impl<'a> RequestObject<'a> {
    /// Starts a request object signed by `key`.
    #[must_use]
    pub fn builder(key: &'a FixtureKey) -> Self {
        Self {
            key,
            client_id: None,
            nonce: DEFAULT_NONCE.to_string(),
            response_type: "vp_token".to_string(),
            response_mode: "dc_api.jwt".to_string(),
            audience: "https://self-issued.me/v2".to_string(),
            state: None,
            dcql_query: serde_json::json!({
                "credentials": [{
                    "id": "fixture-credential",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [DEFAULT_VCT] },
                    "claims": [{ "path": ["name"] }]
                }]
            }),
            client_metadata: serde_json::json!({
                "vp_formats_supported": { "dc+sd-jwt": {} }
            }),
            overrides: Map::new(),
        }
    }

    /// Sets `client_id`. Defaults to `decentralized_identifier:<the key's DID>`,
    /// which is the form whose DID matches the `kid` header.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the `nonce` the holder must echo back.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Sets `response_type`, e.g. `vp_token` or `vp_token id_token`.
    #[must_use]
    pub fn response_type(mut self, response_type: impl Into<String>) -> Self {
        self.response_type = response_type.into();
        self
    }

    /// Sets `response_mode`.
    #[must_use]
    pub fn response_mode(mut self, response_mode: impl Into<String>) -> Self {
        self.response_mode = response_mode.into();
        self
    }

    /// Sets `aud`, which OID4VP 1.0 §5.8 requires on a signed request object.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Sets `state`.
    #[must_use]
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Replaces the DCQL query.
    #[must_use]
    pub fn dcql_query(mut self, dcql_query: Value) -> Self {
        self.dcql_query = dcql_query;
        self
    }

    /// Replaces `client_metadata`.
    #[must_use]
    pub fn client_metadata(mut self, client_metadata: Value) -> Self {
        self.client_metadata = client_metadata;
        self
    }

    /// Overrides or adds a raw request parameter.
    #[must_use]
    pub fn parameter(mut self, name: impl Into<String>, value: Value) -> Self {
        self.overrides.insert(name.into(), value);
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
        params.insert("response_type".to_string(), Value::from(self.response_type));
        params.insert("response_mode".to_string(), Value::from(self.response_mode));
        params.insert("nonce".to_string(), Value::from(self.nonce));
        params.insert("aud".to_string(), Value::from(self.audience));
        params.insert("dcql_query".to_string(), self.dcql_query);
        params.insert("client_metadata".to_string(), self.client_metadata);
        if let Some(state) = self.state {
            params.insert("state".to_string(), Value::from(state));
        }
        merge(&mut params, self.overrides);

        sign_compact(self.key, REQUEST_OBJECT_TYP, &Value::Object(params)).await
    }
}
