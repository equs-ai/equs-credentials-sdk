use async_trait::async_trait;
use oauth2::TokenResponse as _TokenResponse;
use url::Url;

use crate::exchange::oid4vc::oid4vci::holder::{AuthzOption, Oid4VciHolder};
use crate::facade::facade_low_level::Holder;
use crate::facade::facade_oid4vc;
use crate::facade::facade_oid4vc::{Credential, CredentialMetadata, CredentialResult, IssuerMetadata, TokenResponse};
use crate::impls::http::HttpClient;

pub type Error = facade_oid4vc::Error;
pub type Result<T> = facade_oid4vc::Result<T>;

pub struct HolderService<HC, HL>
where
    HC: HttpClient,
    HL: Holder,
{
    holder: Oid4VciHolder<HC, HL>,
}

impl<HC, HL> HolderService<HC, HL>
where
    HC: HttpClient,
    HL: Holder,
{
    pub fn new(holder: Oid4VciHolder<HC, HL>) -> Self {
        Self { holder }
    }
}

#[async_trait]
impl<HC, HL> facade_oid4vc::HolderVci for HolderService<HC, HL>
where
    HC: HttpClient,
    HL: Holder,
{
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.holder.get_issuer_metadata()
    }

    async fn authz_code_flow_with_scope(&self,
                                        cred_def_id: String,
                                        authorization_callback: impl FnOnce(Url) -> String + Send,
    ) -> Result<TokenResponse> {
        let response = self.holder.authz_code_flow(
            // TODO: advanced AuthDetail by cred_def_id, scope is enough for MVP
            AuthzOption::Scope(cred_def_id),
            authorization_callback,
        ).await?;

        Ok(response)
    }

    async fn pre_authz_code_flow(&self,
                                 pre_authorized_code: String,
                                 tx_code: String,
                                 cred_def_id: Option<String>,
    ) -> Result<TokenResponse> {
        let response = self.holder.pre_authorized_flow(
            pre_authorized_code,
            tx_code,
            // TODO: advanced AuthDetail by cred_def_id, scope is enough for MVP
            cred_def_id.map(|id| AuthzOption::Scope(id)),
        ).await?;

        Ok(response)
    }

    async fn request_credential(&self,
                                token_response: &TokenResponse,
                                cred_def_id: &str,
    ) -> Result<CredentialResult> {
        let nonce = token_response.extra_fields().clone().c_nonce.map(|n| n.secret().clone());
        let cred_res = self.holder.request_credential(
            token_response.access_token(),
            cred_def_id,
            nonce,
        ).await?;

        Ok(cred_res)
    }

    async fn store_credential(
        &mut self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()> {
        let _ = self.holder.store_credential(credential, credential_metadata).await?;

        Ok(())
    }
}