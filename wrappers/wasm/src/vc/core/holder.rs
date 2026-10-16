use super::{HolderBinder, JsHolderMetadata, Presentation, PresentationInput, VCStatus};
use crate::did::UniversalDIDResolver;
use crate::http::ReqwestHttpClient;
use crate::kms::{JsKms, Kms};
use crate::utils;
use crate::vault::{JsVault, Vault};
use crate::vc::core::types::{
    WasmCredentialOffer, WasmCredentialRequest, WasmHolderMetadata, WasmPresentation, WasmVCStatus,
};
use crate::vc::{
    Credential, CredentialEntry, CredentialOffer, JsCredential, JsCredentialEntry,
    JsCredentialsFindResult,
};
use equs_sdk::vc::core::{Holder, HolderMetadata, HolderService as CoreHolderService};
use std::sync::Arc;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

// Alias the extern CredentialMetadata to avoid a name clash with the SDK type used
// internally via the fully-qualified path.
use crate::vc::CredentialMetadata as JsCredentialMetadata;

// Alias the extern KeyMetadata (from crypto.rs) — the SDK KeyMetadata is referenced via
// the full path `equs_sdk::vc::core::KeyMetadata` inside the function bodies.
use crate::crypto::KeyMetadata as JsKeyMetadata;

/// A low-level protocol-agnostic `Holder` API.
///
/// Supports credential issuance and presentation flow.
#[wasm_bindgen]
pub struct VcCoreHolder(Box<dyn Holder>);

#[wasm_bindgen]
impl VcCoreHolder {
    /// Creates a new `VCCoreHolder`.
    ///
    /// @param {Kms} kms - the key-management service for signing operations.
    /// @param {Vault} vault - vault for storing and retrieving credentials.
    /// @param {HolderMetadata} metadata - holder configuration (DID, formats).
    /// @param {UniversalDIDResolver} didResolver - DID resolver used during issuance and presentation.
    /// @param {ReqwestHttpClient} httpClient - HTTP client for status-list lookups.
    #[wasm_bindgen(constructor)]
    pub fn new(
        kms: Kms,
        vault: Vault,
        metadata: JsHolderMetadata,
        did_resolver: &UniversalDIDResolver,
        http_client: &ReqwestHttpClient,
    ) -> Result<Self, JsError> {
        let wasm_meta: WasmHolderMetadata = utils::convert_to_rust_object(metadata)?;
        let metadata: HolderMetadata = wasm_meta.try_into()?;
        let holder_service = CoreHolderService::new(
            JsKms::new(kms),
            JsVault::new(vault),
            metadata,
            did_resolver.0.clone(),
            Arc::new(http_client.inner()),
        );
        Ok(VcCoreHolder(Box::new(holder_service)))
    }

    /// Prepares a credential request from a credential offer.
    ///
    /// @param {CredentialOffer} credentialOffer - the offer defining what credential to request.
    /// @param {string} [nonce] - nonce to generate a proof of possession.
    /// @param {KeyMetadata} keyMetadata - key to use for signing.
    /// @returns {Promise<CredentialRequest>}
    #[wasm_bindgen(js_name = requestCredential)]
    pub async fn request_credential(
        &self,
        credential_offer: CredentialOffer,
        nonce: Option<String>,
        key_metadata: JsKeyMetadata,
    ) -> Result<super::CredentialRequest, JsError> {
        let wasm_offer: WasmCredentialOffer = utils::convert_to_rust_object(credential_offer)?;
        let equs_sdk_offer = wasm_offer.try_into()?;
        let equs_sdk_key_metadata: equs_sdk::vc::core::KeyMetadata =
            utils::convert_to_rust_object(key_metadata)?;

        let request = self
            .0
            .request_credential(
                &equs_sdk_offer,
                nonce.map(equs_sdk::nonce::Nonce::from_secret),
                &equs_sdk_key_metadata,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let wasm_request: WasmCredentialRequest = request.into();
        utils::convert_to_opaque_object_unchecked(wasm_request)
    }

    /// Stores a credential in the vault.
    ///
    /// @param {Credential} credential - the credential to store.
    /// @param {CredentialMetadata} metadata - corresponding credential metadata.
    /// @returns {Promise<string>} the stored entry ID.
    #[wasm_bindgen(js_name = storeCredential)]
    pub async fn store_credential(
        &self,
        credential: Credential,
        metadata: JsCredentialMetadata,
    ) -> Result<String, JsError> {
        let js_credential: JsCredential = utils::convert_to_rust_object(credential)?;
        let equs_sdk_credential = js_credential.try_into()?;
        let equs_sdk_metadata: equs_sdk::vc::CredentialMetadata =
            utils::convert_to_rust_object(metadata)?;

        self.0
            .store_credential(&equs_sdk_credential, &equs_sdk_metadata)
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Verifies a credential's signature.
    ///
    /// @param {Credential} credential - the credential to verify.
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = verifyCredential)]
    pub async fn verify_credential(&self, credential: Credential) -> Result<(), JsError> {
        let js_credential: JsCredential = utils::convert_to_rust_object(credential)?;
        let equs_sdk_credential = js_credential.try_into()?;

        self.0
            .verify_credential(&equs_sdk_credential)
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Creates a presentation automatically by selecting the first matching credential.
    ///
    /// @param {HolderBinder} [holderBinder] - optional holder binding (nonce + verifier ID).
    /// @param {PresentationInput} presentationInput - describes the requested VCs.
    /// @returns {Promise<Presentation>}
    #[wasm_bindgen(js_name = createPresentationAuto)]
    pub async fn create_presentation_auto(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation_input: PresentationInput,
    ) -> Result<Presentation, JsError> {
        let equs_sdk_holder_binder = super::decode_holder_binder(holder_binder)?;

        let wasm_input: crate::vc::core::types::WasmPresentationInput =
            utils::convert_to_rust_object(presentation_input)?;
        let equs_sdk_input = wasm_input.try_into()?;

        let presentation = self
            .0
            .create_presentation_auto(equs_sdk_holder_binder, &equs_sdk_input)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let wasm_pres: WasmPresentation = presentation.try_into()?;
        utils::convert_to_opaque_object_unchecked(wasm_pres)
    }

    /// Finds credentials matching the presentation input.
    ///
    /// @param {PresentationInput} presentationInput - describes the requested VCs.
    /// @returns {Promise<CredentialsFindResult>}
    #[wasm_bindgen(js_name = findVcsForPresentation)]
    pub async fn find_vcs_for_presentation(
        &self,
        presentation_input: PresentationInput,
    ) -> Result<JsCredentialsFindResult, JsError> {
        let wasm_input: crate::vc::core::types::WasmPresentationInput =
            utils::convert_to_rust_object(presentation_input)?;
        let equs_sdk_input = wasm_input.try_into()?;

        let result = self
            .0
            .find_vcs_for_presentation(&equs_sdk_input)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let wasm_result: crate::vc::CredentialsFindResult = result.try_into()?;
        utils::convert_to_opaque_object_unchecked(wasm_result)
    }

    /// Creates a presentation with a specific credential.
    ///
    /// @param {HolderBinder} [holderBinder] - optional holder binding.
    /// @param {PresentationInput} presentationInput - describes the requested VCs.
    /// @param {CredentialEntry} credential - the specific credential to use.
    /// @returns {Promise<Presentation>}
    #[wasm_bindgen(js_name = createPresentation)]
    pub async fn create_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation_input: PresentationInput,
        credential: CredentialEntry,
    ) -> Result<Presentation, JsError> {
        let equs_sdk_holder_binder = super::decode_holder_binder(holder_binder)?;

        let wasm_input: crate::vc::core::types::WasmPresentationInput =
            utils::convert_to_rust_object(presentation_input)?;
        let equs_sdk_input = wasm_input.try_into()?;

        let js_entry: JsCredentialEntry = utils::convert_to_rust_object(credential)?;
        let equs_sdk_entry: equs_sdk::vault::CredentialEntry = js_entry.try_into()?;

        let presentation = self
            .0
            .create_presentation(equs_sdk_holder_binder, &equs_sdk_input, &equs_sdk_entry)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let wasm_pres: WasmPresentation = presentation.try_into()?;
        utils::convert_to_opaque_object_unchecked(wasm_pres)
    }

    /// Gets the status of a credential.
    ///
    /// @param {Credential} credential - the credential containing the status claim.
    /// @returns {Promise<VCStatus | undefined>}
    #[wasm_bindgen(js_name = getCredentialStatus)]
    pub async fn get_credential_status(
        &self,
        credential: Credential,
    ) -> Result<Option<VCStatus>, JsError> {
        let js_credential: JsCredential = utils::convert_to_rust_object(credential)?;
        let equs_sdk_credential = js_credential.try_into()?;

        let status = self
            .0
            .get_credential_status(&equs_sdk_credential)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        status
            .map(|s| -> Result<VCStatus, JsError> {
                let wasm_status: WasmVCStatus = s.try_into()?;
                utils::convert_to_opaque_object_unchecked(wasm_status)
            })
            .transpose()
    }
}
