use crate::common::Result;
use crate::did::universal_resolver::UniversalDIDResolver;
use crate::http::{HttpClient, WrappedHttpClient};
use crate::kms::{Kms, WrappedKms};
use crate::vault::{CredentialsFindResult, Vault, WrappedVault};
use crate::vc::core::types::{
    CredentialOffer, CredentialRequest, HolderBinder, HolderMetadata, PresentationInput,
};
use crate::vc::{Credential, CredentialMetadata, VCStatus};
use agent_sdk::nonce::Nonce;
use agent_sdk::vault::CredentialEntry;
use agent_sdk::vc::Presentation;
use agent_sdk::vc::core::{Holder, HolderService, KeyMetadata};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct VCCoreHolder(pub(crate) Box<dyn Holder>);

#[uniffi::export]
impl VCCoreHolder {
    #[uniffi::constructor]
    pub fn new(
        kms: Arc<dyn Kms>,
        vault: Arc<dyn Vault>,
        metadata: HolderMetadata,
        did_resolver: Arc<UniversalDIDResolver>,
        http_client: Arc<dyn HttpClient>,
    ) -> Result<Self> {
        let service = HolderService::new(
            WrappedKms::new(kms),
            WrappedVault::new(vault),
            metadata,
            did_resolver.inner().clone(),
            Arc::new(WrappedHttpClient::new(http_client)),
        );
        Ok(Self(Box::new(service)))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VCCoreHolder {
    pub async fn request_credential(
        &self,
        credential_offer: CredentialOffer,
        nonce: Option<String>,
        key_metadata: KeyMetadata,
    ) -> Result<CredentialRequest> {
        Ok(self
            .0
            .request_credential(
                &credential_offer.into(),
                nonce.map(Nonce::from_secret),
                &key_metadata,
            )
            .await?)
    }

    pub async fn store_credential(
        &self,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<String> {
        Ok(self.0.store_credential(&credential, &metadata).await?)
    }

    pub async fn verify_credential(&self, credential: Credential) -> Result<()> {
        Ok(self.0.verify_credential(&credential).await?)
    }

    pub async fn create_presentation_auto(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation_input: PresentationInput,
    ) -> Result<Presentation> {
        Ok(self
            .0
            .create_presentation_auto(holder_binder, &presentation_input)
            .await?)
    }

    pub async fn find_vcs_for_presentation(
        &self,
        presentation_input: PresentationInput,
    ) -> Result<CredentialsFindResult> {
        Ok(self
            .0
            .find_vcs_for_presentation(&presentation_input)
            .await?
            .into())
    }

    pub async fn create_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation_input: PresentationInput,
        credential: CredentialEntry,
    ) -> Result<Presentation> {
        Ok(self
            .0
            .create_presentation(holder_binder, &presentation_input, &credential)
            .await?)
    }

    pub async fn get_credential_status(&self, credential: Credential) -> Result<Option<VCStatus>> {
        Ok(self.0.get_credential_status(&credential).await?)
    }
}
