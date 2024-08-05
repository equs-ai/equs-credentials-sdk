use anyhow::Error;
use oid4vp::core::{
    authorization_request::AuthorizationRequestObject,
    credential_format::CredentialFormat,
    metadata::WalletMetadata,
    profile::{Profile, Verifier},
};

use crate::exchange::oid4vc::oid4vp::presentation_builder::DefaultPresentationBuilder;

pub struct SdJwtVc;

impl CredentialFormat for SdJwtVc {
    const ID: &'static str = "sd+jwt-vc";
}

#[derive(Clone)]
pub struct DefaultVerifierProfile;

impl Profile for DefaultVerifierProfile {
    type CredentialFormat = SdJwtVc;

    fn validate_request(
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
