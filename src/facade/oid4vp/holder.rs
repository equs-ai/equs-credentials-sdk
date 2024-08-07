use async_trait::async_trait;
use oid4vp::core::metadata::WalletMetadata;
use url::Url;

use crate::core_::{kms, vault};
use crate::exchange::oid4vc::oid4vp::holder::{Oid4VpHolder, ResolvedAuthRequest};
use crate::facade::facade_low_level;
use crate::facade::facade_oid4vc::{AuthorizationResponseMetadata, CredentialMapping, HolderVp};
use crate::facade::facade_oid4vc::Result;
use crate::impls::did::UniversalResolver;

pub struct HolderService {
    holder: Oid4VpHolder,
    http_client: reqwest::Client,
}

impl HolderService {
    pub fn new<KH>(
        client_id: String,
        metadata: Option<WalletMetadata>,
        did_url: String,
        kid: String,
        kms: impl kms::Kms<KH> + 'static,
        vault: impl vault::Vault + 'static,
        http_client: reqwest::Client,
    ) -> Self
    where
        KH: kms::KeyHandle + 'static,
    {
        let holder_metadata = facade_low_level::HolderMetadata {
            client_id,
            key_metadata: facade_low_level::KeyMetadata { did_url, kid },
        };
        let holder_low_level = facade_low_level::HolderService::new(kms, vault, holder_metadata);
        let holder = Oid4VpHolder::new(
            metadata,
            holder_low_level,
            UniversalResolver::new(),
            http_client.clone(),
        );

        Self {
            holder,
            http_client,
        }
    }
}

#[async_trait]
impl HolderVp for HolderService {
    async fn get_authorization_request(&self, auth_req_uri: &str) -> Result<ResolvedAuthRequest> {
        let url = Url::parse(auth_req_uri)?;
        let resolved_req = self.holder.resolve_authorization_request(&url).await?;

        Ok(resolved_req)
    }

    async fn present_credentials_auto(&self, auth_request: &ResolvedAuthRequest, _: &AuthorizationResponseMetadata) -> Result<Option<Url>> {
        let url = self.holder.submit_authorization_response(&auth_request).await?;

        Ok(url)
    }

    async fn find_vcs_for_presentation(&self, auth_request: &ResolvedAuthRequest) -> Result<CredentialMapping> {
        let creds_map = self.holder.get_vcs_for_presentation(auth_request).await?;

        Ok(creds_map)
    }

    async fn present_credentials(&self, auth_request: &ResolvedAuthRequest, credential_mapping_selected: &CredentialMapping, _: &AuthorizationResponseMetadata) -> Result<Option<Url>> {
        let url = self.holder.submit_authorization_response_selected(&auth_request, credential_mapping_selected).await?;

        Ok(url)
    }
}