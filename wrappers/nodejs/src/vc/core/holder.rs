use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::vault::{JsCredentialEntry, JsVault, NativeVault, UnifiedVault};
use crate::vc::core::{JsCredential, JsCredentialMetadata, JsHolderMetadata, JsKeyMetadata};
use crate::vc::core::{
    JsCredentialOffer, JsCredentialRequest, JsPresentation, JsPresentationInput,
};
use agent_sdk::vc::core::{Holder, HolderService as CoreHolderService};
use napi::{Either, Error};
use napi_derive::napi;
use serde_json::Value;

#[napi]
pub struct VCCoreHolder(pub(crate) Box<dyn Holder>);

#[napi]
impl VCCoreHolder {
    #[napi]
    pub async fn request_credential(
        &self,
        credential_offer: JsCredentialOffer,
        nonce: String,
        key_metadata: JsKeyMetadata,
    ) -> Result<JsCredentialRequest, Error> {
        self.0
            .request_credential(
                &credential_offer.try_into()?,
                &serde_json::from_value(Value::String(nonce))?,
                &key_metadata.into(),
            )
            .await
            .map(|v| v.into())
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn store_credential(
        &self,
        credential: JsCredential,
        metadata: JsCredentialMetadata,
    ) -> Result<String, Error> {
        self.0
            .store_credential(&credential.try_into()?, &metadata.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn verify_credential(&self, credential: JsCredential) -> Result<(), Error> {
        self.0
            .verify_credential(&credential.try_into()?)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn create_presentation_auto(
        &self,
        nonce: String,
        verifier_id: String,
        presentation_input: JsPresentationInput,
    ) -> Result<JsPresentation, Error> {
        self.0
            .create_presentation_auto(
                &serde_json::from_value(Value::String(nonce))?,
                &verifier_id,
                &presentation_input.try_into()?,
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|v| v.try_into())
    }

    #[napi]
    pub async fn find_vcs_for_presentation(
        &self,
        presentation_input: JsPresentationInput,
    ) -> Result<Vec<JsCredentialEntry>, Error> {
        self.0
            .find_vcs_for_presentation(&presentation_input.try_into()?)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|value| {
                let mut vector: Vec<JsCredentialEntry> = vec![];
                for cred_entry in value {
                    vector.push(cred_entry.try_into()?);
                }
                Ok(vector)
            })
    }

    #[napi]
    pub async fn create_presentation(
        &self,
        nonce: String,
        verifier_id: String,
        presentation_input: JsPresentationInput,
        credential: JsCredentialEntry,
    ) -> Result<JsPresentation, Error> {
        self.0
            .create_presentation(
                &serde_json::from_value(Value::String(nonce))?,
                &verifier_id,
                &presentation_input.try_into()?,
                &credential.try_into()?,
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|v| v.try_into())
    }
}

#[allow(unused)]
#[napi]
pub fn create_holder(
    kms: Either<&NativeKms, JsKms>,
    vault: Either<&NativeVault, JsVault>,
    metadata: JsHolderMetadata,
) -> VCCoreHolder {
    let kms: UnifiedKms = kms.into();
    let vault: UnifiedVault = vault.into();
    let metadata = metadata.into();
    let holder_service = CoreHolderService::new(kms, vault, metadata);
    VCCoreHolder(Box::new(holder_service))
}
