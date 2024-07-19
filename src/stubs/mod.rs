#![allow(dead_code)]
#![allow(unused_variables)]

use oauth2::url::Url;
use oid4vci::openidconnect::Nonce;

use crate::core_::{crypto, did, pop, vc};
use crate::core_::did::DIDURL;
use crate::core_::kms;
use crate::core_::kms::KeyID;
use crate::core_::pop::{ProofOfPossession, VerifyOptions};
use crate::core_::pop::jwt_pop::Proof;
use crate::core_::vault::FindCriteria;
use crate::core_::vc::{API, Error};
use crate::core_::vc::sd_jwt_vc::{Claims, Credential, Presentation, VCMetadata, VPMetadata};
use crate::exchange::oid4vc;
use crate::exchange::oid4vc::AccessToken;
use crate::exchange::oid4vc::vci::{AuthorizationResponse, CredentialOffer, CredentialOfferParams, CredentialRequest, CredentialResult};
use crate::impls::kms::inmem::LocalKms;

mod demo;

// core::did

pub struct _DIDCore
{
    kms: LocalKms,
}

impl _DIDCore {
    pub fn new(kms: LocalKms) -> Self {
        Self { kms }
    }
}

impl did::DIDCore for _DIDCore {
    async fn create<S: crypto::Signer>(method: did::DIDMethod, signer: S, options: did::CreateOptions) -> Result<did::Created, did::DIDError> {
        todo!()
    }

    async fn resolve(did: &did::DID, options: did::ResolveOptions) -> Result<did::Resolution, did::DIDError> {
        todo!()
    }

    async fn update(did: &did::DID, options: did::UpdateOptions) -> Result<did::Updated, did::DIDError> {
        todo!()
    }

    async fn deactivate(did: &did::DID, options: did::DeactivateOptions) -> Result<did::Deactivated, did::DIDError> {
        todo!()
    }
}

// core::vc

pub struct _SdJwtAPI;

impl _SdJwtAPI {
    pub fn new() -> Self {
        Self {}
    }
}

impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata> for _SdJwtAPI {
    async fn create_vc<S>(claims: Claims, signer: S, iss_did_url: &DIDURL, metadata: VCMetadata) -> Result<Credential, Error>
    where
        S: crypto::Signer,
    {
        todo!()
    }

    async fn create_vp<S>(credential: &Credential, signer: S, nonce: vc::Nonce, verifier_id: &str, holder_did_url: &DIDURL, metadata: VPMetadata) -> Result<Presentation, Error>
    where
        S: crypto::Signer,
    {
        todo!()
    }

    async fn verify_vp(presentation: &Presentation, opts: vc::VerifyOptions) -> Result<(), Error> {
        todo!()
    }
}

impl vc::sd_jwt_vc::SdJwtAPI for _SdJwtAPI {}

pub struct _JwtProofOfPossessionAPI;

impl _JwtProofOfPossessionAPI {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProofOfPossession<Proof> for _JwtProofOfPossessionAPI {
    async fn generate<S>(did_url: &DIDURL, signer: S, nonce: vc::Nonce, aud: String, iss: Option<String>) -> Result<Proof, Error>
    where
        S: crypto::Signer,
    {
        todo!()
    }

    async fn verify(proof: Proof, opts: VerifyOptions) -> Result<(), Error> {
        todo!()
    }
}

impl pop::jwt_pop::JwtProofOfPossession for _JwtProofOfPossessionAPI {}

// exchange::oid4vc

pub struct _Issuer
{
    metadata: oid4vc::vci::IssuerMetadata,
    kms: LocalKms,
}

impl _Issuer {
    pub fn new(kms: LocalKms, metadata: oid4vc::vci::IssuerMetadata) -> Self {
        Self { kms, metadata }
    }
}

impl oid4vc::vci::Issuer for _Issuer {
    async fn metadata(&self) -> oid4vc::vci::IssuerMetadata {
        todo!()
    }

    async fn offer_pre_authz_flow(&self, code: &str, cred_ids: &Vec<String>) -> Result<CredentialOfferParams, oid4vc::Error> {
        todo!()
    }

    async fn offer_authz_flow(&self, iss_state: Option<String>, cred_ids: &Vec<String>) -> Result<CredentialOfferParams, oid4vc::Error> {
        todo!()
    }

    async fn validate_token(&self, token: AccessToken) -> Result<(), oid4vc::Error> {
        todo!()
    }

    async fn validate_request(&self, req: CredentialRequest) -> Result<(), oid4vc::Error> {
        todo!()
    }

    async fn verify_proof(&self, pop: oid4vc::vci::Proof, nonce: Nonce) -> Result<(), oid4vc::Error> {
        todo!()
    }

    async fn issue_credential<CM>(&self, req: CredentialRequest, claims: CM, did_url: DIDURL, key_id: KeyID) -> Result<vc::Credential, oid4vc::Error> {
        todo!()
    }
}

pub struct _Holder {}

impl oid4vc::vci::Holder for _Holder {
    async fn from_metadata(issuer_url: Url) -> Result<Self, oid4vc::Error> {
        todo!()
    }

    async fn from_offer(offer: CredentialOffer) -> Result<Self, oid4vc::Error> {
        todo!()
    }

    fn supported_cred_ids() -> Vec<String> {
        todo!()
    }

    async fn authz_code_flow(&self, cred_ids: &Vec<String>, callback: fn(Url) -> String) -> Result<AuthorizationResponse, oid4vc::Error> {
        todo!()
    }

    async fn pre_authorized_flow(&self, cred_ids: &Vec<String>) -> Result<AuthorizationResponse, oid4vc::Error> {
        todo!()
    }

    async fn request(&self, token: AccessToken, req: CredentialRequest,
                     nonce: Option<vc::Nonce>, proof_did_url: Option<DIDURL>, proof_kid: Option<KeyID>,
    ) -> Result<CredentialResult, oid4vc::Error> {
        todo!()
    }


    async fn deferred(&self, token: AccessToken, transaction_id: String) -> Result<CredentialResult, oid4vc::Error> {
        todo!()
    }
}
