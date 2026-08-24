use crate::common::{Error, JsonValue, Result};
use crate::did::universal_resolver::UniversalDIDResolver;
use crate::kms::{Kms, WrappedKms};
use crate::vc::Credential;
use crate::vc::core::types::{
    CredentialOffer, CredentialOfferData, CredentialRequest, CredentialStatusInfo, IssuerMetadata,
};
use equs_sdk::nonce::Nonce;
use equs_sdk::vc::core::{Issuer, IssuerService, PrepareCredential};
use std::sync::Arc;

trait IssuerWithPrepare: Issuer + PrepareCredential {}
impl<T> IssuerWithPrepare for T where T: Issuer + PrepareCredential + ?Sized {}

#[derive(uniffi::Object)]
pub struct VCCoreIssuer(Box<dyn IssuerWithPrepare>);

#[uniffi::export]
impl VCCoreIssuer {
    #[uniffi::constructor]
    pub fn new(
        kms: Arc<dyn Kms>,
        metadata: IssuerMetadata,
        did_resolver: Arc<UniversalDIDResolver>,
    ) -> Result<Self> {
        let service = IssuerService::new(
            WrappedKms::new(kms),
            metadata.into(),
            did_resolver.inner().clone(),
        );
        Ok(Self(Box::new(service)))
    }

    pub fn offer_credential(
        &self,
        cred_def_id: String,
        protocol_data: Option<CredentialOfferData>,
    ) -> Result<CredentialOffer> {
        Ok(self
            .0
            .offer_credential(&cred_def_id, protocol_data.as_ref())?
            .into())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VCCoreIssuer {
    pub async fn issue_credential(
        &self,
        credential_request: CredentialRequest,
        claims: JsonValue,
        nonce: Option<String>,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<Credential> {
        let claims = claims
            .try_into()
            .map_err(|e: equs_sdk::vc::claims::Error| Error::Core(e.to_string()))?;
        Ok(self
            .0
            .issue_credential(
                &credential_request,
                &claims,
                nonce.map(Nonce::from_secret),
                status_info,
            )
            .await?)
    }

    pub async fn prepare_credential(
        &self,
        credential_request: CredentialRequest,
        claims: JsonValue,
        nonce: Option<String>,
        status_info: Option<CredentialStatusInfo>,
    ) -> Result<JsonValue> {
        let claims = claims
            .try_into()
            .map_err(|e: equs_sdk::vc::claims::Error| Error::Core(e.to_string()))?;
        let unsigned = self
            .0
            .prepare_credential(
                &credential_request,
                &claims,
                nonce.map(Nonce::from_secret),
                status_info,
            )
            .await?;
        serde_json::to_value(unsigned)
            .map_err(|e| Error::Core(format!("failed to serialize UnsignedCredential: {e}")))
    }
}
