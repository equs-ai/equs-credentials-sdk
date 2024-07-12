use oid4vci::openidconnect::Nonce;

use crate::core_::{did, vault, vc};
use crate::core_::kms;
use crate::core_::kms::{KeyID, PubKey};
use crate::core_::vault::{FindCriteria, VaultError};
use crate::core_::vc::{Credential, CredentialMaterial, GenerationOptions, ToCredential, VCError};
use crate::exchange::oid4vc;

// core::kms

pub struct KeyHandle;
pub struct Kms;

impl Kms {
    pub fn new() -> Self {
        Self {}
    }
}

impl kms::Signer for KeyHandle {
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, kms::KmsError> {
        todo!()
    }
}

impl kms::Verifier for KeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), kms::KmsError> {
        todo!()
    }
}

impl kms::Kms<KeyHandle> for Kms {
    async fn create(key_type: kms::KeyType, options: kms::CreateOptions) -> Result<kms::KeyID, kms::KmsError> {
        todo!()
    }

    async fn get(key_id: kms::KeyID) -> Result<KeyHandle, kms::KmsError> {
        todo!()
    }

    async fn pub_key(key_id: kms::KeyID) -> Result<impl PubKey, kms::KmsError> {
        todo!()
    }
}

// core::did

pub struct DIDCore
{
    kms: Kms,
}

impl DIDCore {
    pub fn new(kms: Kms) -> Self {
        Self { kms }
    }
}

impl did::DIDCore for DIDCore {
    async fn create(method: did::DIDMethod, options: did::CreateOptions) -> Result<did::Created, did::DIDError> {
        todo!()
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

pub struct Vault {
    kms: Kms,
}

impl vault::Vault for Vault {
    fn open(master_secret: String) -> Result<(), VaultError> {
        todo!()
    }

    fn close() -> Result<(), VaultError> {
        todo!()
    }

    async fn store_credential(credential: Credential) -> Result<String, VaultError> {
        todo!()
    }

    async fn get_credential(id: String) -> Result<Credential, VaultError> {
        todo!()
    }

    async fn find_credentials(criteria: FindCriteria) -> Result<Vec<Credential>, VaultError> {
        todo!()
    }
}

// core::vc

impl ToCredential for CredentialMaterial {
    async fn to_credential(&self, signer: impl kms::Signer, options: GenerationOptions) -> Result<Credential, VCError> {
        todo!()
    }
}

// exchange::oid4vc

pub struct Issuer
{
    metadata: oid4vc::IssuerMetadata,
    kms: Kms,
}

impl oid4vc::Issuer for Issuer {
    async fn metadata() -> oid4vc::IssuerMetadata {
        todo!()
    }

    async fn validate_token(token: oid4vc::AccessToken) -> Result<(), oid4vc::OidError> {
        todo!()
    }

    async fn validate_request(req: oid4vc::CredentialRequest) -> Result<(), oid4vc::OidError> {
        todo!()
    }

    async fn verify_proof(pop: oid4vc::ProofOfPossession, nonce: Option<Nonce>) -> Result<(), oid4vc::OidError> {
        todo!()
    }

    async fn issue_credential(req: oid4vc::CredentialRequest, material: impl vc::ToCredential, key_id: KeyID) -> Result<Credential, oid4vc::OidError> {
        todo!()
    }
}

