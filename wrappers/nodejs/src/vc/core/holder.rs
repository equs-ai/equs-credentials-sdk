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

/// An async low-level protocol-agnostic `Holder` API.
///
/// Supports issuance and presentation flow.
///
/// @property requestCredential - {@link VCCoreHolder.requestCredential}
/// @property storeCredential - {@link VCCoreHolder.storeCredential}
/// @property verifyCredential - {@link VCCoreHolder.verifyCredential}
/// @property createPresentationAuto - {@link VCCoreHolder.createPresentationAuto}
/// @property findVcsForPresentation - {@link VCCoreHolder.findVcsForPresentation}
/// @property createPresentation - {@link VCCoreHolder.createPresentation}
#[napi]
pub struct VCCoreHolder(pub(crate) Box<dyn Holder>);

#[napi]
impl VCCoreHolder {
    /// Prepare a {@link CredentialRequest}.
    ///
    /// @param {CredentialOffer} credentialOffer - a {@link CredentialOffer} with definition of which {@link Credential} to request.
    /// @param {string} nonce - a nonce to generate a `ProofOfPossession`.
    /// @param {KeyMetadata} keyMetadata - a {@link KeyMetadata} for corresponding key to be used for signing operations.
    ///
    /// @returns {CredentialRequest} - A {@link CredentialRequest} to be used by `Issuer` on success.
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

    /// Store a {@link Credential}.
    ///
    /// This method will store the `credential` into the {@link Vault} under the hood.
    ///
    /// @param {Credential} credential - a {@link Credential} to save.
    /// @param {CredentialMetadata} metadata - the corresponding {@link CredentialMetadata}.
    ///
    /// @returns {string} - An ID of the entry on success.
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

    /// Verify a {@link Credential} against an Issuer signature.
    ///
    /// This method will validate the `credential` signature.
    ///
    /// @param {Credential} credential - a {@link Credential} to save.
    ///
    /// @returns {void}
    #[napi]
    pub async fn verify_credential(&self, credential: JsCredential) -> Result<(), Error> {
        self.0
            .verify_credential(&credential.try_into()?)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Create a Verifiable Presentation automatically.
    ///
    /// `Holder` will automatically select first {@link Credential} that matched the {@link PresentationInput}.
    ///
    /// @param {string} `nonce` - a nonce form {@link Verifier} to be used to generate `VP`.
    /// @param {string} `verifierId` - an ID of the {@link Verifier}.
    /// @param {PresentationInput} `presentationInput` - an input with data related to requested `VC`s.
    ///
    /// @returns {Presentation}
    /// * A generated {@link Presentation} on success
    /// * Error will be thrown if no suitable {@link Credential} was found
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

    /// Find the suitable {@link CredentialEntry}s for the provided {@link PresentationInput}.
    ///
    /// @param {PresentationInput} presentationInput - an input with data related to requested `VC`s.
    ///
    /// @returns {Array<CredentialEntry>}
    /// * An array of {@link CredentialEntry} matched the provided {@link PresentationInput} on success
    /// * An empty array if nothing meets the `presentationInput`
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

    /// Create a Verifiable Presentation.
    ///
    /// @param {string} `nonce` - a nonce from {@link Verifier} to be used to generate `VP`.
    /// @param {string} `verifierId` - an ID of the {@link Verifier}.
    /// @param {PresentationInput} `presentationInput` - an input with the data defining the requested `VC`s.
    /// @param {CredentialEntry} `credential` - an actual {@link CredentialEntry} for the {@link Presentation}.
    ///
    /// @returns {Presentation} - A generated {@link Presentation} on success.
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
