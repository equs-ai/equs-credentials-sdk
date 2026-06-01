use crate::did::JsUniversalDIDResolver;
use crate::error::IntoNapiError;
use crate::http::ReqwestHttpClient;
use crate::kms::JsKms;
use crate::vault::{JsCredentialEntry, JsCredentialsFindResult, JsVault};
use crate::vc::core::{JsCredential, JsCredentialMetadata, JsHolderMetadata, JsKeyMetadata};
use crate::vc::core::{
    JsCredentialOffer, JsCredentialRequest, JsPresentation, JsPresentationInput,
};
use crate::vc::core::{JsHolderBinder, JsVCStatus};
use agent_sdk::vc::core::{Holder, HolderService as CoreHolderService};
use napi::Error;
use napi_derive::napi;
use std::sync::Arc;

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
#[napi(js_name = "_VcCoreHolder")]
pub struct VCCoreHolder(pub(crate) Box<dyn Holder>);

#[napi]
impl VCCoreHolder {
    /// Build a new `VCCoreHolder`.
    ///
    /// @param {Kms} kms - the key-management service used for signing operations.
    /// @param {Vault} vault - vault for storing and retrieving credentials.
    /// @param {HolderMetadata} metadata - holder configuration (DID, formats).
    /// @param {_UniversalDIDResolver} didResolver - DID resolver used during issuance and presentation.
    /// @param {ReqwestHttpClient} httpClient - HTTP client for status-list lookups.
    #[napi(constructor)]
    pub fn new(
        kms: JsKms,
        vault: JsVault,
        metadata: JsHolderMetadata,
        did_resolver: &JsUniversalDIDResolver,
        http_client: &ReqwestHttpClient,
    ) -> Result<Self, Error> {
        let metadata = metadata.try_into()?;
        let holder_service = CoreHolderService::new(
            kms,
            vault,
            metadata,
            did_resolver.into(),
            Arc::new(http_client.inner()),
        );
        Ok(Self(Box::new(holder_service)))
    }

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
        nonce: Option<String>,
        key_metadata: JsKeyMetadata,
    ) -> Result<JsCredentialRequest, Error> {
        self.0
            .request_credential(
                &credential_offer.try_into()?,
                nonce.map(agent_sdk::nonce::Nonce::from_secret),
                &key_metadata.into(),
            )
            .await
            .map(|v| v.into())
            .map_err(IntoNapiError::into_napi_error)
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
            .map_err(IntoNapiError::into_napi_error)
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
            .map_err(IntoNapiError::into_napi_error)
    }

    /// Create a Verifiable Presentation automatically.
    ///
    /// `Holder` will automatically select first {@link Credential} that matched the {@link PresentationInput}.
    ///
    /// @param {holder_binder} - if given: bind holder in the credential. It contains nonce and verifier_id
    /// @param {PresentationInput} `presentationInput` - an input with data related to requested `VC`s.
    ///
    /// @returns {Presentation}
    /// * A generated {@link Presentation} on success
    /// * Error will be thrown if no suitable {@link Credential} was found
    #[napi]
    pub async fn create_presentation_auto(
        &self,
        holder_binder: Option<JsHolderBinder>,
        presentation_input: JsPresentationInput,
    ) -> Result<JsPresentation, Error> {
        self.0
            .create_presentation_auto(
                holder_binder.map(Into::into),
                &presentation_input.try_into()?,
            )
            .await
            .map_err(IntoNapiError::into_napi_error)
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
    ) -> Result<JsCredentialsFindResult, Error> {
        self.0
            .find_vcs_for_presentation(&presentation_input.try_into()?)
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(|value| value.try_into())
    }

    /// Create a Verifiable Presentation.
    ///
    /// @param {holder_binder} - if given: bind holder in the credential. It contains nonce and verifier_id
    /// @param {PresentationInput} `presentationInput` - an input with the data defining the requested `VC`s.
    /// @param {CredentialEntry} `credential` - an actual {@link CredentialEntry} for the {@link Presentation}.
    ///
    /// @returns {Presentation} - A generated {@link Presentation} on success.
    #[napi]
    pub async fn create_presentation(
        &self,
        holder_binder: Option<JsHolderBinder>,
        presentation_input: JsPresentationInput,
        credential: JsCredentialEntry,
    ) -> Result<JsPresentation, Error> {
        self.0
            .create_presentation(
                holder_binder.map(Into::into),
                &presentation_input.try_into()?,
                &credential.try_into()?,
            )
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(|v| v.try_into())
    }

    /// Gets the status for Credential.
    ///
    /// @param {Credential} credential - a {@link Credential} containing the status claim.
    ///
    /// @returns {VCStatus} VC Status on success
    #[napi]
    pub async fn get_credential_status(
        &self,
        credential: JsCredential,
    ) -> Result<Option<JsVCStatus>, Error> {
        let status = self
            .0
            .get_credential_status(&credential.try_into()?)
            .await
            .map_err(IntoNapiError::into_napi_error)?;

        status.map(TryInto::try_into).transpose()
    }
}

// TODO(next-release): remove `create_holder` — superseded by `new VcCoreHolder(...)`.
/// @deprecated Use `new VcCoreHolder(kms, vault, metadata, didResolver, httpClient)` instead.
/// This factory will be removed in the next release.
#[allow(unused)]
#[napi]
pub fn create_holder(
    kms: JsKms,
    vault: JsVault,
    metadata: JsHolderMetadata,
    did_resolver: &JsUniversalDIDResolver,
    http_client: &ReqwestHttpClient,
) -> Result<VCCoreHolder, napi::Error> {
    tracing::warn!(
        "`createHolder` is deprecated and will be removed in the next release. \
         Use `new VcCoreHolder(kms, vault, metadata, didResolver, httpClient)` instead."
    );
    VCCoreHolder::new(kms, vault, metadata, did_resolver, http_client)
}
