use agent_sdk::vc::oid4vp::ResolvedAuthRequest;
use std::collections::HashMap;

use crate::common::Result;
use crate::common::{Duration, Error, JsonValue};
use crate::crypto::KeyMetadata;
use crate::utils::parse_url_arg;

mod builder;
pub mod holder;

pub type IdTokenMetadata = agent_sdk::vc::oid4vp::IdTokenMetadata;
pub type AuthorizationResponseMetadata = agent_sdk::vc::oid4vp::AuthorizationResponseMetadata;

#[uniffi::remote(Record)]
pub struct IdTokenMetadata {
    pub key_metadata: KeyMetadata,
    pub lifetime: Duration,
}

#[uniffi::remote(Record)]
pub struct AuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
    pub id_token_metadata: Option<IdTokenMetadata>,
}

#[derive(uniffi::Record)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub client_metadata: JsonValue,
    pub presentation_definition: JsonValue,
    pub nonce: String,
    pub response_type: String,
    pub response_mode: String,
    pub response_uri: String,
    pub state: Option<String>,
}

impl TryFrom<AuthorizationRequest> for ResolvedAuthRequest {
    type Error = Error;

    fn try_from(value: AuthorizationRequest) -> Result<Self> {
        Ok(ResolvedAuthRequest {
            client_id: value.client_id,
            client_metadata: serde_json::from_value(value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            resolved_presentation_query: serde_json::from_value(value.presentation_definition)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: parse_url_arg(&value.response_uri)
                .map_err(|err| Error::OID4VPHolder(format!("{err:?}")))?,
            state: value.state,
        })
    }
}

impl TryFrom<ResolvedAuthRequest> for AuthorizationRequest {
    type Error = Error;

    fn try_from(value: ResolvedAuthRequest) -> Result<Self> {
        Ok(AuthorizationRequest {
            client_id: value.client_id,
            client_metadata: serde_json::to_value(&value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            presentation_definition: serde_json::to_value(&value.resolved_presentation_query)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: value.nonce.secret().to_string(),
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: value.response_uri.to_string(),
            state: value.state,
        })
    }
}
