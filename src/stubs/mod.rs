use oauth2::url::Url;
use oid4vci::openidconnect::Nonce;

use crate::core_::{crypto, did, pop, vault, vc};
use crate::core_::crypto::{Alg, Signer};
use crate::core_::did::{Created, DIDURL};
use crate::core_::kms;
use crate::core_::kms::KeyID;
use crate::core_::pop::{ProofOfPossession, VerifyOptions};
use crate::core_::pop::jwt_pop::{JwtProofOfPossession, Proof};
use crate::core_::vault::{FindCriteria, VaultError};
use crate::core_::vc::{API, Error};
use crate::core_::vc::sd_jwt_vc::{Claims, Credential, Presentation, VCMetadata, VPMetadata};
use crate::exchange::oid4vc;
use crate::exchange::oid4vc::AccessToken;
use crate::exchange::oid4vc::vci::{AuthorizationResponse, CredentialOffer, CredentialOfferParams, CredentialRequest, CredentialResult};

mod demo;

// core::kms

#[derive(Clone)]
pub struct _KeyHandle;

pub struct _Kms;

impl _Kms {
    pub fn new() -> Self {
        Self {}
    }
}

impl crypto::Signer for _KeyHandle {
    fn alg() -> Alg {
        Alg::ES256
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::CryptoError> {
        todo!()
    }
}

impl crypto::Verifier for _KeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::CryptoError> {
        todo!()
    }
}

impl kms::KeyHandle for _KeyHandle {}

impl kms::Kms<_KeyHandle> for _Kms {
    async fn create(&self, key_type: kms::KeyType, options: kms::CreateOptions) -> Result<kms::KeyID, kms::KmsError> {
        todo!()
    }

    async fn get(&self, key_id: &kms::KeyID) -> Result<_KeyHandle, kms::KmsError> {
        todo!()
    }

    async fn pub_key(&self, key_id: &kms::KeyID) -> Result<Box<dyn kms::PubKey>, kms::KmsError> {
        todo!()
    }
}

// core::did

pub struct _DIDCore
{
    kms: _Kms,
}

impl _DIDCore {
    pub fn new(kms: _Kms) -> Self {
        Self { kms }
    }
}

impl did::DIDCore for _DIDCore {
    async fn create<S: crypto::Signer>(method: did::DIDMethod, signer: S, options: did::CreateOptions) -> Result<did::Created, did::DIDError> {
        println!("Generated DID");
        Ok(Created { did: Some("did:example:123".into()), ..Default::default() })
    }

    async fn resolve(did: &did::DID, options: crate::core_::did::ResolveOptions) -> Result<did::Resolution, did::DIDError> {
        todo!()
    }

    async fn update(did: &did::DID, options: crate::core_::did::UpdateOptions) -> Result<did::Updated, did::DIDError> {
        todo!()
    }

    async fn deactivate(did: &did::DID, options: crate::core_::did::DeactivateOptions) -> Result<did::Deactivated, did::DIDError> {
        todo!()
    }
}

// core::vault

pub struct _Vault;

impl _Vault {
    pub fn new() -> Self {
        Self {}
    }
}

impl vault::Vault for _Vault {
    fn open(&self, master_secret: &str) -> Result<(), VaultError> {
        println!("Vault opened");
        Ok(())
    }

    fn close(&self) -> Result<(), VaultError> {
        todo!()
    }

    async fn store_credential(&self, credential: vc::Credential) -> Result<String, VaultError> {
        todo!()
    }

    async fn get_credential(&self, id: String) -> Result<vc::Credential, VaultError> {
        todo!()
    }

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<vc::Credential>, VaultError> {
        todo!()
    }
}

pub struct _KeyStorage;

impl _KeyStorage {
    pub fn new() -> Self {
        Self {}
    }
}

impl vault::Storage<DIDURL, kms::KeyID> for _KeyStorage {
    async fn put(&self, k: &DIDURL, v: &kms::KeyID) -> Result<(), VaultError> {
        todo!()
    }

    async fn get(&self, k: &DIDURL) -> Result<kms::KeyID, VaultError> {
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
    kms: _Kms,
}

impl _Issuer {
    pub fn new(kms: _Kms, metadata: oid4vc::vci::IssuerMetadata) -> Self {
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

    async fn validate_request(&self, req: oid4vc::vci::CredentialRequest) -> Result<(), oid4vc::Error> {
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
