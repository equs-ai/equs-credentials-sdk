use crate::did::JsUniversalDIDResolver;
use crate::kms::JsKms;
use crate::vc::core::{JsCredential, JsIssuerMetadata};
use crate::vc::core::{
    JsCredentialOffer, JsCredentialOfferData, JsCredentialRequest, JsCredentialStatusInfo,
};
use agent_sdk::vc::claims::Error as ClaimsError;
use agent_sdk::vc::core::{Issuer, IssuerMetadata, IssuerService as CoreIssuerService};
use napi::Error;
use napi_derive::napi;
use serde_json::Value;

/// An async low-level protocol-agnostic `Issuer` API.
///
/// Provides the methods for creating a {@link CredentialOffer} and issuing a {@link Credential}.
///
/// @property offerCredential - {@link VCCoreIssuer.offerCredential}
/// @property issueCredential - {@link VCCoreIssuer.issueCredential}
///
#[napi]
pub struct VCCoreIssuer(pub(crate) Box<dyn Issuer>);

#[napi]
impl VCCoreIssuer {
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
            .map_err(|e| Error::from_reason(e.to_string()))
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
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|v| v.try_into())
    }
}

#[allow(unused)]
#[napi]
pub fn create_issuer(
    kms: JsKms,
    metadata: JsIssuerMetadata,
    did_resolver: &JsUniversalDIDResolver,
) -> Result<VCCoreIssuer, Error> {
    let metadata: IssuerMetadata = metadata.try_into()?;
    let issuer_service = CoreIssuerService::new(kms, metadata, did_resolver.into());
    Ok(VCCoreIssuer(Box::new(issuer_service)))
}
