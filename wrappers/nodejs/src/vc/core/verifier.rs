use crate::did::JsUniversalDIDResolver;
use crate::error::IntoNapiError;
use crate::http::{JsHttpClient, ReqwestHttpClient};
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use crate::vc::core::JsPresentation;
use crate::vc::core::JsVCStatus;
use agent_sdk::vc::core::{Verifier, VerifierService as CoreVerifierService};
use napi::Error;
use napi_derive::napi;
use serde_json::Value;

/// An async low-level protocol-agnostic {@link Verifier} API.
///
/// Provides basic method for verification of `VP`s.
///
/// @property verifyPresentation - {@link VCCoreVerifier.verifyPresentation}
/// @property obtainCredentialStatus - {@link VCCoreVerifier.obtainCredentialStatus}
#[napi]
pub struct VCCoreVerifier(pub(crate) Box<dyn Verifier>);

#[napi]
impl VCCoreVerifier {
    /// Verify a {@link Presentation}.
    ///
    /// @param {string} nonce - a nonce used to generate {@link Presentation}.
    /// @param {Presentation} presentation - a {@link Presentation} to verify.
    /// @param {ReqwestHttpClient} httpClient - an {@link ReqwestHttpClient} http client
    ///
    /// @returns {Claims} Verified {@link Claims} on success.
    #[napi(ts_return_type = "Promise<Claims>")]
    pub async fn verify_presentation(
        &self,
        nonce: String,
        presentation: JsPresentation,
        http_client: &ReqwestHttpClient,
    ) -> Result<JsonObject, Error> {
        self.0
            .verify_presentation(
                &serde_json::from_value(Value::String(nonce))?,
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

#[allow(unused)]
#[napi]
pub fn create_verifier(
    verifier_id: String,
    did_resolver: &JsUniversalDIDResolver,
) -> VCCoreVerifier {
    let verifier_service = CoreVerifierService::new(&verifier_id, did_resolver.into());
    VCCoreVerifier(Box::new(verifier_service))
}
