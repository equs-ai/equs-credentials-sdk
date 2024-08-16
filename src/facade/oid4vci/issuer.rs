use async_trait::async_trait;
use oauth2::http::HeaderValue;
use oid4vci::core::profiles::CoreProfilesOffer;
use oid4vci::credential_offer::{CredentialOfferGrants, CredentialOfferParameters};
use url::Url;

use crate::core_::storage::Storage;
use crate::exchange::oid4vc::oid4vci::{CredentialRequest, CredentialResponse, IssuerMetadata};
use crate::exchange::oid4vc::oid4vci::issuer::Oid4VciIssuer;
use crate::facade::facade_low_level::Issuer;
use crate::facade::facade_oid4vc;
use crate::facade::facade_oid4vc::CredentialClaims;
use crate::impls::http::HttpClient;

pub type Error = facade_oid4vc::Error;
pub type Result<T> = facade_oid4vc::Result<T>;

pub struct IssuerService<HC, IS, ST>
where
    HC: HttpClient,
    IS: Issuer,
    ST: Storage<String, serde_json::Value>,
{
    oid4vci_issuer: Oid4VciIssuer<HC, IS>,
    storage: ST,
}

#[async_trait]
impl<HC, IS, ST> facade_oid4vc::Issuer for IssuerService<HC, IS, ST>
where
    HC: HttpClient,
    IS: Issuer,
    ST: Storage<String, serde_json::Value>,
{
    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParameters<CoreProfilesOffer>, Url)> {
        let offer = self
            .oid4vci_issuer
            .create_credential_offer(cred_def_ids, grants)?;

        Ok(offer)
    }

    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.oid4vci_issuer.metadata()
    }

    async fn issue_credential(
        &mut self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &CredentialClaims,
    ) -> Result<CredentialResponse> {
        //TODO: Implement another option to get a nonce from the token
        if let Ok(nonce_value) = self.storage.get(token).await {
            let nonce = serde_json::from_value(nonce_value.to_owned())?;

            let (cred, cred_metadata) = self.oid4vci_issuer
                .issue_credential(cred_request, token, nonce, claims)
                .await?;

            if let Some(value) = serde_json::to_value(&cred_metadata).ok() {
                let _ = self.storage.put(cred_metadata.core_metadata.id, value).await;
            }

            Ok(cred)
        } else {
            let (error, nonce) = self.oid4vci_issuer
                .generate_pop_verification_error_and_nonce();

            if let Ok(nonce) = serde_json::to_value(nonce) {
                let _ = self.storage.put(token.to_string(), nonce).await;
            }

            Err(Error::Issuer(error))
        }
    }
}

impl<HC, IS, ST> IssuerService<HC, IS, ST>
where
    HC: HttpClient + 'static,
    IS: Issuer,
    ST: Storage<String, serde_json::Value>,
{
    pub fn new(
        issuer: IS,
        storage: ST,
        http_client: HC,
        metadata: IssuerMetadata,
        auth_server_admin_auth_header: Option<HeaderValue>,
        token_validation: bool,
    ) -> Self
    {
        let oid4vci_issuer = Oid4VciIssuer::new(metadata, issuer, http_client, auth_server_admin_auth_header, token_validation);

        Self { oid4vci_issuer, storage }
    }
}