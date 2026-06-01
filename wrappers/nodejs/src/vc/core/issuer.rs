use crate::did::JsUniversalDIDResolver;
use crate::error::IntoNapiError;
use crate::kms::JsKms;
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use crate::vc::core::{JsCredential, JsIssuerMetadata};
use crate::vc::core::{
    JsCredentialOffer, JsCredentialOfferData, JsCredentialRequest, JsCredentialStatusInfo,
};
use agent_sdk::vc::claims::Error as ClaimsError;
use agent_sdk::vc::core::{
    Issuer, IssuerMetadata, IssuerService as CoreIssuerService, PrepareCredential,
};
use napi::Error;
use napi_derive::napi;
use serde_json::Value;

/// Trait-object combiner used by [`VCCoreIssuer`] so the boxed service exposes
/// both the high-level [`Issuer`] API and the [`PrepareCredential`] step of
/// the prepare/sign split. Any concrete service that implements both — e.g.
/// `IssuerService` — automatically satisfies it via the blanket impl below.
pub(crate) trait IssuerWithPrepare: Issuer + PrepareCredential {}
impl<T> IssuerWithPrepare for T where T: Issuer + PrepareCredential + ?Sized {}

/// An async low-level protocol-agnostic `Issuer` API.
///
/// Provides the methods for creating a {@link CredentialOffer} and issuing a {@link Credential}.
///
/// @property offerCredential - {@link VCCoreIssuer.offerCredential}
/// @property issueCredential - {@link VCCoreIssuer.issueCredential}
/// @property prepareCredential - {@link VCCoreIssuer.prepareCredential}
///
#[napi(js_name = "_VcCoreIssuer")]
pub struct VCCoreIssuer(pub(crate) Box<dyn IssuerWithPrepare>);

#[napi]
impl VCCoreIssuer {
    /// Build a new `VCCoreIssuer`.
    ///
    /// @param {Kms} kms - the key-management service backing credential signing.
    /// @param {IssuerMetadata} metadata - issuer configuration (DID, formats, etc.).
    /// @param {_UniversalDIDResolver} didResolver - DID resolver used during issuance.
    #[napi(constructor)]
    pub fn new(
        kms: JsKms,
        metadata: JsIssuerMetadata,
        did_resolver: &JsUniversalDIDResolver,
    ) -> Result<Self, Error> {
        let metadata: IssuerMetadata = metadata.try_into()?;
        let issuer_service = CoreIssuerService::new(kms, metadata, did_resolver.into());
        Ok(Self(Box::new(issuer_service)))
    }

    /// Create a {@link CredentialOffer} based on some {@link CredentialDefinition}.
    ///
    ///
    /// Generated {@link CredentialOffer} matches provided {@link CredentialDefinition}
    /// and should be later used by `Holder` to create a corresponding {@link CredentialRequest}.
    ///
    /// @param {string} credDefId - a {@link CredentialDefinition}s ID used for {@link CredentialOffer} creation.
    /// @param {CredentialOfferData} [protocolData] - protocol-specific data.
    ///
    /// @returns {CredentialOffer} - A {@link CredentialOffer} to be shared with `Holder` on success.
    #[napi]
    pub fn offer_credential(
        &self,
        cred_def_id: String,
        protocol_data: Option<JsCredentialOfferData>,
    ) -> Result<JsCredentialOffer, Error> {
        let protocol_data = protocol_data.map(|value| value.into());
        self.0
            .offer_credential(&cred_def_id, protocol_data.as_ref())
            .map_err(IntoNapiError::into_napi_error)
            .and_then(|v| v.try_into())
    }

    /// Issue a {@link Credential} based on the {@link CredentialRequest}.
    ///
    /// {@link CredentialRequest} should match some existing {@link CredentialDefinition} of the `Issuer`.
    ///
    /// @param {CredentialRequest} credentialRequest - a {@link CredentialRequest} used for {@link Credential} generation.
    /// @param {Claims} claims - claims to include into the {@link Credential}.
    /// @param {string} nonce - a nonce to validate the {@link Proof} included in the {@link CredentialRequest}.
    /// @param {CredentialStatusInfo} statusInfo - credential status info
    ///
    /// @returns {Credential} An issued {@link Credential} on success.
    #[napi]
    pub async fn issue_credential(
        &self,
        credential_request: JsCredentialRequest,
        #[napi(ts_arg_type = "Claims")] claims: Value,
        nonce: Option<String>,
        status_info: Option<JsCredentialStatusInfo>,
    ) -> Result<JsCredential, Error> {
        let claims = claims
            .try_into()
            .map_err(|e: ClaimsError| Error::from_reason(e.to_string()))?;

        let status_info = status_info.map(|s| s.try_into()).transpose()?;

        self.0
            .issue_credential(
                &credential_request.into(),
                &claims,
                nonce.map(agent_sdk::nonce::Nonce::from_secret),
                status_info,
            )
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(|v| v.try_into())
    }

    /// First step of the two-step issuance flow: validate the {@link CredentialRequest},
    /// resolve issuer/holder metadata, and produce an {@link UnsignedCredential} ready for
    /// signing.
    ///
    /// The returned value is the externally-tagged JSON shape of the SDK's
    /// `UnsignedCredential` enum — `{ "SdJwt": { ... } }` or `{ "Ldp": { ... } }` —
    /// and can be passed directly to {@link VCCoreCredentialSigner.signCredential}.
    ///
    /// @param {CredentialRequest} credentialRequest - a {@link CredentialRequest} used for {@link Credential} generation.
    /// @param {Claims} claims - claims to include into the {@link Credential}.
    /// @param {string} [nonce] - a nonce to validate the {@link Proof} included in the {@link CredentialRequest}.
    /// @param {CredentialStatusInfo} [statusInfo] - credential status info
    ///
    /// @returns {UnsignedCredential} - the prepared, unsigned credential on success.
    #[napi(ts_return_type = "Promise<UnsignedCredential>")]
    pub async fn prepare_credential(
        &self,
        credential_request: JsCredentialRequest,
        #[napi(ts_arg_type = "Claims")] claims: Value,
        nonce: Option<String>,
        status_info: Option<JsCredentialStatusInfo>,
    ) -> Result<JsonObject, Error> {
        let claims = claims
            .try_into()
            .map_err(|e: ClaimsError| Error::from_reason(e.to_string()))?;

        let status_info = status_info.map(|s| s.try_into()).transpose()?;

        let unsigned = self
            .0
            .prepare_credential(
                &credential_request.into(),
                &claims,
                nonce.map(agent_sdk::nonce::Nonce::from_secret),
                status_info,
            )
            .await
            .map_err(IntoNapiError::into_napi_error)?;

        to_json_object(unsigned)
    }
}

// TODO(next-release): remove `create_issuer` — superseded by `new VcCoreIssuer(...)`.
/// @deprecated Use `new VcCoreIssuer(kms, metadata, didResolver)` instead.
/// This factory will be removed in the next release.
#[allow(unused)]
#[napi]
pub fn create_issuer(
    kms: JsKms,
    metadata: JsIssuerMetadata,
    did_resolver: &JsUniversalDIDResolver,
) -> Result<VCCoreIssuer, Error> {
    tracing::warn!(
        "`createIssuer` is deprecated and will be removed in the next release. \
         Use `new VcCoreIssuer(kms, metadata, didResolver)` instead."
    );
    VCCoreIssuer::new(kms, metadata, did_resolver)
}
