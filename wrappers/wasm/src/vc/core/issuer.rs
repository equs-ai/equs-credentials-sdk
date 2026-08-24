use super::{
    CredentialOfferData, CredentialRequest, CredentialStatusInfo, JsIssuerMetadata,
    WasmUnsignedCredential,
};
use crate::did::UniversalDIDResolver;
use crate::kms::{JsKms, Kms};
use crate::utils;
use crate::utils::Claims;
use crate::vc::core::types::{
    WasmCredentialOffer, WasmCredentialRequest, WasmCredentialStatusInfo, WasmIssuerMetadata,
};
use crate::vc::{Credential, CredentialOffer, JsCredential};
use equs_sdk::vc::core::{
    Issuer, IssuerMetadata, IssuerService as CoreIssuerService, PrepareCredential,
};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

fn decode_issue_params(
    credential_request: CredentialRequest,
    claims: Claims,
    status_info: Option<CredentialStatusInfo>,
) -> Result<
    (
        equs_sdk::vc::core::CredentialRequest,
        equs_sdk::vc::claims::Claims,
        Option<equs_sdk::vc::core::CredentialStatusInfo>,
    ),
    JsError,
> {
    let equs_sdk_request =
        utils::convert_to_rust_object::<_, WasmCredentialRequest>(credential_request)?.into();
    let claims_value: serde_json::Value = utils::convert_to_rust_object(claims)?;
    let equs_sdk_claims = equs_sdk::vc::claims::Claims::try_from(claims_value)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let equs_sdk_status_info = status_info
        .map(|v| {
            utils::convert_to_rust_object::<_, WasmCredentialStatusInfo>(v)
                .and_then(|w| w.try_into())
        })
        .transpose()?;
    Ok((equs_sdk_request, equs_sdk_claims, equs_sdk_status_info))
}

/// Combines [`Issuer`] and [`PrepareCredential`] into a single object-safe trait.
trait IssuerWithPrepare: Issuer + PrepareCredential {}
impl<T> IssuerWithPrepare for T where T: Issuer + PrepareCredential + ?Sized {}

/// A low-level protocol-agnostic `Issuer` API.
///
/// Provides methods for creating a credential offer and issuing credentials.
#[wasm_bindgen]
pub struct VcCoreIssuer(Box<dyn IssuerWithPrepare>);

#[wasm_bindgen]
impl VcCoreIssuer {
    /// Creates a new `VCCoreIssuer`.
    ///
    /// @param {Kms} kms - the key-management service backing credential signing.
    /// @param {IssuerMetadata} metadata - issuer configuration (DID, formats, etc.).
    /// @param {UniversalDIDResolver} didResolver - DID resolver used during issuance.
    #[wasm_bindgen(constructor)]
    pub fn new(
        kms: Kms,
        metadata: JsIssuerMetadata,
        did_resolver: &UniversalDIDResolver,
    ) -> Result<Self, JsError> {
        let wasm_meta: WasmIssuerMetadata = utils::convert_to_rust_object(metadata)?;
        let metadata: IssuerMetadata = wasm_meta.try_into()?;
        let issuer_service =
            CoreIssuerService::new(JsKms::new(kms), metadata, did_resolver.0.clone());
        Ok(VcCoreIssuer(Box::new(issuer_service)))
    }

    /// Creates a credential offer for the given credential definition.
    ///
    /// @param {string} credDefId - the credential definition ID.
    /// @param {CredentialOfferData} [protocolData] - optional protocol-specific data.
    /// @returns {CredentialOffer}
    #[wasm_bindgen(js_name = offerCredential)]
    pub fn offer_credential(
        &self,
        cred_def_id: String,
        protocol_data: Option<CredentialOfferData>,
    ) -> Result<CredentialOffer, JsError> {
        let protocol_data = protocol_data.map(|_| equs_sdk::vc::core::CredentialOfferData {});

        let offer = self
            .0
            .offer_credential(&cred_def_id, protocol_data.as_ref())
            .map_err(|e| JsError::new(&e.to_string()))?;

        let wasm_offer: WasmCredentialOffer = offer.try_into()?;
        utils::convert_to_opaque_object_unchecked(wasm_offer)
    }

    /// Issues a credential based on the credential request.
    ///
    /// @param {CredentialRequest} credentialRequest - the request.
    /// @param {Claims} claims - claims to include in the credential.
    /// @param {string} [nonce] - nonce to validate the proof of possession.
    /// @param {CredentialStatusInfo} [statusInfo] - credential status info.
    /// @returns {Promise<Credential>}
    #[wasm_bindgen(js_name = issueCredential)]
    pub async fn issue_credential(
        &self,
        credential_request: CredentialRequest,
        claims: Claims,
        nonce: Option<String>,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<Credential, JsError> {
        let (equs_sdk_request, equs_sdk_claims, equs_sdk_status_info) =
            decode_issue_params(credential_request, claims, status_info)?;

        let credential = self
            .0
            .issue_credential(
                &equs_sdk_request,
                &equs_sdk_claims,
                nonce.map(equs_sdk::nonce::Nonce::from_secret),
                equs_sdk_status_info,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let js_credential: JsCredential = credential.try_into()?;
        utils::convert_to_opaque_object_unchecked(js_credential)
    }

    /// First step of the two-step issuance flow: validate the request and produce an
    /// unsigned credential ready for signing.
    ///
    /// Returns the externally-tagged JSON shape of the SDK's `UnsignedCredential` enum —
    /// `{ "SdJwt": { ... } }` or `{ "Ldp": { ... } }` — which can be passed directly to
    /// {@link VCCoreCredentialSigner.signCredential}.
    ///
    /// @param {CredentialRequest} credentialRequest - the request.
    /// @param {Claims} claims - claims to include in the credential.
    /// @param {string} [nonce] - nonce to validate the proof of possession.
    /// @param {CredentialStatusInfo} [statusInfo] - credential status info.
    /// @returns {Promise<UnsignedCredential>}
    #[wasm_bindgen(js_name = prepareCredential)]
    pub async fn prepare_credential(
        &self,
        credential_request: CredentialRequest,
        claims: Claims,
        nonce: Option<String>,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<WasmUnsignedCredential, JsError> {
        let (equs_sdk_request, equs_sdk_claims, equs_sdk_status_info) =
            decode_issue_params(credential_request, claims, status_info)?;

        let unsigned = self
            .0
            .prepare_credential(
                &equs_sdk_request,
                &equs_sdk_claims,
                nonce.map(equs_sdk::nonce::Nonce::from_secret),
                equs_sdk_status_info,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        utils::convert_to_opaque_object_unchecked(unsigned)
    }
}
