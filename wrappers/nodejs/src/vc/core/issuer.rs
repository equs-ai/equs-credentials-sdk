use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::vc::core::{JsCredential, JsIssuerMetadata};
use crate::vc::core::{
    JsCredentialOffer, JsCredentialOfferData, JsCredentialRequest, JsCredentialStatusInfo,
};
use agent_sdk::vc::claims::Error as ClaimsError;
use agent_sdk::vc::core::{Issuer, IssuerMetadata, IssuerService as CoreIssuerService};
use napi::{Either, Error};
use napi_derive::napi;
use serde_json::Value;

#[napi]
pub struct VCCoreIssuer(pub(crate) Box<dyn Issuer>);

#[napi]
impl VCCoreIssuer {
    #[napi]
    pub fn offer_credential(
        &self,
        cred_def_id: String,
        protocol_data: Option<JsCredentialOfferData>,
    ) -> Result<JsCredentialOffer, Error> {
        let protocol_data = protocol_data.map(|value| value.into());
        self.0
            .offer_credential(&cred_def_id, protocol_data.as_ref())
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|v| v.try_into())
    }

    #[napi]
    pub async fn issue_credential(
        &self,
        credential_request: JsCredentialRequest,
        #[napi(ts_arg_type = "Claims")] claims: Value,
        nonce: String,
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
                &serde_json::from_value(Value::String(nonce))?,
                status_info,
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|v| v.try_into())
    }
}

#[allow(unused)]
#[napi]
pub fn create_issuer(
    kms: Either<&NativeKms, JsKms>,
    metadata: JsIssuerMetadata,
) -> Result<VCCoreIssuer, Error> {
    let kms: UnifiedKms = kms.into();
    let metadata: IssuerMetadata = metadata.try_into()?;
    let issuer_service = CoreIssuerService::new(kms, metadata);
    Ok(VCCoreIssuer(Box::new(issuer_service)))
}
