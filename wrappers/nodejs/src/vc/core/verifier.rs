use crate::http::JsHttpClient;
use crate::utils::to_json_object;
use crate::vc::core::JsPresentation;
use crate::vc::core::JsVCStatus;
use crate::vc::JsonObject;
use agent_sdk::vc::core::{Verifier, VerifierService as CoreVerifierService};
use napi::Error;
use napi_derive::napi;
use serde_json::Value;

#[napi]
pub struct VCCoreVerifier(pub(crate) Box<dyn Verifier>);

#[napi]
impl VCCoreVerifier {
    #[napi(ts_return_type = "Promise<Claims>")]
    pub async fn verify_presentation(
        &self,
        nonce: String,
        presentation: JsPresentation,
    ) -> Result<JsonObject, Error> {
        self.0
            .verify_presentation(
                &serde_json::from_value(Value::String(nonce))?,
                &presentation.try_into()?,
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(to_json_object)
    }

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
            .map_err(|e| Error::from_reason(e.to_string()))?;

        result.map(TryInto::try_into).transpose()
    }
}

#[allow(unused)]
#[napi]
pub fn create_verifier(verifier_id: String) -> VCCoreVerifier {
    let verifier_service = CoreVerifierService::new(&verifier_id);
    VCCoreVerifier(Box::new(verifier_service))
}
