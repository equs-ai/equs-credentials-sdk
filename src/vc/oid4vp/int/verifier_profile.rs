use anyhow::Error;
use async_trait::async_trait;
use oid4vp::core::{
    authorization_request::AuthorizationRequestObject
    ,
    metadata::WalletMetadata,
    profile::{Profile, Verifier},
};
use oid4vp::core::credential_format::CoreCredentialFormat;

use crate::vc::oid4vp::int::presentation_builder::DefaultPresentationBuilder;

#[derive(Clone)]
pub struct DefaultVerifierProfile;

#[async_trait]
impl Profile for DefaultVerifierProfile {
    type CredentialFormat = CoreCredentialFormat;

    async fn validate_request(
        &self,
        wallet_metadata: &WalletMetadata,
        request_object: &AuthorizationRequestObject,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Verifier for DefaultVerifierProfile {
    type PresentationBuilder = DefaultPresentationBuilder;
}
