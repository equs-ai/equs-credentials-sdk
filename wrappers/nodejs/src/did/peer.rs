use crate::did::{JsVerificationMethodKey, JsVerificationRelationshipType};
use crate::utils::from_json_object;
use crate::vc::JsonObject;
use agent_sdk::did::didpeer::{DIDPeer, DidPeerService};
use agent_sdk::did::{VerificationMethodKey, VerificationRelationshipType};
use napi::Error;
use napi_derive::napi;

#[napi(js_name = "DIDPeer")]
pub struct JsDIDPeer;

#[allow(clippy::new_without_default)]
#[napi]
impl JsDIDPeer {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self
    }

    #[napi]
    pub fn generate_did_peer4(
        keys: Vec<&JsVerificationMethodKey>,
        #[napi(ts_arg_type = "Array<Service>")] services: Vec<JsonObject>,
    ) -> napi::Result<String> {
        let vm_keys: Vec<VerificationMethodKey> =
            keys.iter().map(|key| key.to_owned().into()).collect();
        let parsed_services = services
            .into_iter()
            .map(from_json_object::<DidPeerService>)
            .collect::<napi::Result<Vec<_>>>()?;
        let service_refs = parsed_services.as_slice();

        DIDPeer::generate_did_peer4(&vm_keys, service_refs)
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

impl<'a> From<&'a JsVerificationMethodKey> for VerificationMethodKey<'a> {
    fn from(value: &'a JsVerificationMethodKey) -> Self {
        VerificationMethodKey {
            key: &value.key,
            verification_relationships: value
                .verification_relationships
                .iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<&JsVerificationRelationshipType> for VerificationRelationshipType {
    fn from(value: &JsVerificationRelationshipType) -> Self {
        match value {
            JsVerificationRelationshipType::Authentication => {
                VerificationRelationshipType::Authentication
            }
            JsVerificationRelationshipType::Assertion => VerificationRelationshipType::Assertion,
            JsVerificationRelationshipType::KeyAgreement => {
                VerificationRelationshipType::KeyAgreement
            }
            JsVerificationRelationshipType::CapabilityInvocation => {
                VerificationRelationshipType::CapabilityInvocation
            }
            JsVerificationRelationshipType::CapabilityDelegation => {
                VerificationRelationshipType::CapabilityDelegation
            }
        }
    }
}
