use crate::did::JsUniversalDIDResolver;
use crate::error::IntoNapiError;
use crate::http::{JsHttpClient, ReqwestHttpClient};
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use crate::vc::core::JsHolderBinder;
use crate::vc::core::JsPresentation;
use crate::vc::core::JsVCStatus;
use agent_sdk::vc::core::{Verifier, VerifierService as CoreVerifierService};
use napi::Error;
use napi_derive::napi;

/// An async low-level protocol-agnostic {@link Verifier} API.
///
/// Provides basic method for verification of `VP`s.
///
/// @property verifyPresentation - {@link VCCoreVerifier.verifyPresentation}
/// @property obtainCredentialStatus - {@link VCCoreVerifier.obtainCredentialStatus}
#[napi(js_name = "_VcCoreVerifier")]
pub struct VCCoreVerifier(pub(crate) Box<dyn Verifier>);

#[napi]
impl VCCoreVerifier {
    /// Build a new `VCCoreVerifier`.
    ///
    /// @param {string} verifierId - identifier for this verifier (used as `aud`).
    /// @param {_UniversalDIDResolver} didResolver - DID resolver used during verification.
    #[napi(constructor)]
    pub fn new(verifier_id: String, did_resolver: &JsUniversalDIDResolver) -> Self {
        let verifier_service = CoreVerifierService::new(&verifier_id, did_resolver.into());
        Self(Box::new(verifier_service))
    }

    /// Verify a {@link Presentation}.
    ///
    /// @param {holder_binder} - if given used to bind holder in the credential. It contains nonce and verifier_id
    /// @param {Presentation} presentation - a {@link Presentation} to verify.
    /// @param {ReqwestHttpClient} httpClient - an {@link ReqwestHttpClient} http client
    ///
    /// @returns {Claims} Verified {@link Claims} on success.
    #[napi(ts_return_type = "Promise<Claims>")]
    pub async fn verify_presentation(
        &self,
        holder_binder: Option<JsHolderBinder>,
        presentation: JsPresentation,
        http_client: &ReqwestHttpClient,
    ) -> Result<JsonObject, Error> {
        self.0
            .verify_presentation(
                holder_binder.map(Into::into),
                &presentation.try_into()?,
                &http_client.inner(),
            )
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(to_json_object)
    }

    /// Obtains the status for presented VC.
    ///
    /// @param {Presentation} presentation - a {@link Presentation} containing VC data.
    /// @param {HttpClient} httpClient - a http client.
    ///
    /// @returns {VCStatus} VC Status on success
    #[napi]
    pub async fn obtain_credential_status(
        &self,
        presentation: JsPresentation,
        http_client: JsHttpClient,
    ) -> Result<Option<JsVCStatus>, Error> {
        let result = self
            .0
            .obtain_credential_status(&presentation.try_into()?, &http_client)
            .await
            .map_err(IntoNapiError::into_napi_error)?;

        result.map(TryInto::try_into).transpose()
    }
}

// TODO(next-release): remove `create_verifier` — superseded by `new VcCoreVerifier(...)`.
/// @deprecated Use `new VcCoreVerifier(verifierId, didResolver)` instead.
/// This factory will be removed in the next release.
#[allow(unused)]
#[napi]
pub fn create_verifier(
    verifier_id: String,
    did_resolver: &JsUniversalDIDResolver,
) -> VCCoreVerifier {
    tracing::warn!(
        "`createVerifier` is deprecated and will be removed in the next release. \
         Use `new VcCoreVerifier(verifierId, didResolver)` instead."
    );
    VCCoreVerifier::new(verifier_id, did_resolver)
}
