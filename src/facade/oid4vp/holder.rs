use async_trait::async_trait;
use oid4vp::core::metadata::WalletMetadata;
use url::Url;

use crate::core_::did::DIDResolver;
use crate::exchange::oid4vc::oid4vp::holder::{Oid4VpHolder, ResolvedAuthRequest};
use crate::facade::facade_low_level::Holder;
use crate::facade::facade_oid4vc::{AuthorizationResponseMetadata, CredentialMapping, HolderVp};
use crate::facade::facade_oid4vc::Result;

pub struct HolderService<HL, D>
where
    HL: Holder,
    D: DIDResolver,
{
    holder: Oid4VpHolder<HL, D>,
}

impl<HL, D> HolderService<HL, D>
where
    HL: Holder,
    D: DIDResolver,
{
    pub fn new(
        holder_low_level: HL,
        resolver: D,
        metadata: Option<WalletMetadata>,
        http_client: reqwest::Client,
    ) -> Self {
        let holder = Oid4VpHolder::new(
            metadata,
            holder_low_level,
            resolver,
            http_client,
        );

        Self { holder }
    }
}

#[async_trait]
impl<HL, D> HolderVp for HolderService<HL, D>
where
    HL: Holder,
    D: DIDResolver,
{
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