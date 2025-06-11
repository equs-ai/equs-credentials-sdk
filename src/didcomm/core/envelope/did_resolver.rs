use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;
use ssi::dids::DIDBuf;
use ssi::dids::document::verification_method::ValueOrReference;

use crate::did::universal::UniversalResolver;
use crate::did::{DIDDoc, DIDResolver};

#[derive(Clone)]
pub struct DidResolverWrapper(UniversalResolver);

impl DidResolverWrapper {
    pub fn new(did_resolver: UniversalResolver) -> Self {
        DidResolverWrapper(did_resolver)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl didcomm::did::DIDResolver for DidResolverWrapper {
    async fn resolve(&self, did: &str) -> didcomm::error::Result<Option<didcomm::did::DIDDoc>> {
        let did_buf = DIDBuf::from_string(did.to_string())
            .map_err(|err| didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err))?;

        let document = self
            .0
            .resolve(did_buf.as_did())
            .await
            .map_err(|err| {
                didcomm::error::Error::new(didcomm::error::ErrorKind::DIDNotResolved, err)
            })?
            .document;

        convert_did_doc(document).map(Some)
    }
}

fn convert_did_doc(did_doc: DIDDoc) -> didcomm::error::Result<didcomm::did::DIDDoc> {
    let did_doc = didcomm::did::DIDDoc {
        id: did_doc.id.to_string(),
        key_agreement: did_doc
            .verification_relationships
            .key_agreement
            .iter()
            .map(|vm| get_verification_method_id(&did_doc.id, vm))
            .collect(),
        authentication: did_doc
            .verification_relationships
            .authentication
            .iter()
            .map(|vm| get_verification_method_id(&did_doc.id, vm))
            .collect(),
        verification_method: did_doc
            .verification_method
            .iter()
            .map(convert_to_didcomm_object)
            .collect::<didcomm::error::Result<Vec<_>>>()?,
        service: did_doc
            .service
            .iter()
            .map(convert_to_didcomm_object)
            .collect::<didcomm::error::Result<Vec<_>>>()?,
    };

    Ok(did_doc)
}

fn get_verification_method_id(base_id: &ssi::dids::DID, vm: &ValueOrReference) -> String {
    match vm {
        ValueOrReference::Reference(reference) => reference.resolve(base_id).to_string(),
        ValueOrReference::Value(value) => value.id.to_string(),
    }
}

fn convert_to_didcomm_object<T: Serialize, R: DeserializeOwned>(
    object: T,
) -> didcomm::error::Result<R> {
    serde_json::to_value(object)
        .and_then(serde_json::from_value)
        .map_err(|err| didcomm::error::Error::new(didcomm::error::ErrorKind::Malformed, err))
}
