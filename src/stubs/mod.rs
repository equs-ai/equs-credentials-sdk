use std::iter::Map;

use oid4vci::openidconnect::Nonce;
use serde_json::Value;

use crate::core_::{did, vault, vc};
use crate::core_::did::{Created, DID};
use crate::core_::kms;
use crate::core_::kms::{KeyID, PubKey, Signer};
use crate::core_::vault::{FindCriteria, VaultError};
use crate::core_::vc::{Credential, CredentialMaterial, GenerationOptions, Presentation, ProofPreparation, ProofPrepare, ToCredential, VCError, W3cBuilder, W3cVc, W3cVcSubj};
use crate::exchange::oid4vc;

mod demo;

// core::kms

pub struct _KeyHandle;
pub struct _Kms;

impl _Kms {
    pub fn new() -> Self {
        Self {}
    }
}

impl kms::Signer for _KeyHandle {
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, kms::KmsError> {
        todo!()
    }
}

impl kms::Verifier for _KeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), kms::KmsError> {
        todo!()
    }
}

impl kms::KeyHandle for _KeyHandle {}

impl kms::Kms<_KeyHandle> for _Kms {
    async fn create(&self, key_type: kms::KeyType, options: kms::CreateOptions) -> Result<kms::KeyID, kms::KmsError> {
        todo!()
    }

    async fn get(&self, key_id: kms::KeyID) -> Result<_KeyHandle, kms::KmsError> {
        todo!()
    }

    async fn pub_key(&self, key_id: kms::KeyID) -> Result<Box<dyn PubKey>, kms::KmsError> {
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
    async fn create(method: did::DIDMethod, options: did::CreateOptions) -> Result<did::Created, did::DIDError> {
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

    async fn store_credential(&self, credential: Credential) -> Result<String, VaultError> {
        todo!()
    }

    async fn get_credential(&self, id: String) -> Result<Credential, VaultError> {
        todo!()
    }

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<Credential>, VaultError> {
        todo!()
    }
}

pub struct _KeyStorage;

impl _KeyStorage {
    pub fn new() -> Self {
        Self {}
    }
}

impl vault::Storage<DID, KeyID> for _KeyStorage {
    async fn put(&self, k: &DID, v: &KeyID) -> Result<(), VaultError> {
        todo!()
    }

    async fn get(&self, k: &DID) -> Result<Option<KeyID>, VaultError> {
        todo!()
    }
}

// core::vc
pub struct _W3cBuilder;

impl vc::W3cBuilder for _W3cBuilder {
    fn subject(&self, arg: W3cVcSubj) -> _W3cBuilder {
        todo!()
    }

    fn subject_from_did(&self, arg: &DID) -> _W3cBuilder {
        todo!()
    }

    fn claims(&self, arg: Map<String, Value>) -> _W3cBuilder {
        todo!()
    }

    fn claims_from_json(&self, arg: Value) -> _W3cBuilder {
        todo!()
    }

    fn build(&self) -> W3cVc {
        todo!()
    }
}

pub struct DIDProof {
    did: DID,
}

impl DIDProof {
    pub fn new(did: DID) -> Self {
        Self { did }
    }
}

impl ProofPrepare for DIDProof {
    async fn prepare(&self) -> ProofPreparation {
        todo!()
    }
}

pub struct _VC;

impl _VC {
    pub fn new() -> Self {
        Self {}
    }
}

impl vc::VC for _VC {
    type Options = ();

    async fn generate<S, P>(cred: CredentialMaterial, proof_gen: P, signer: S, options: ()) -> Result<Credential, VCError>
    where
        S: Signer,
        P: ProofPrepare,
    {
        todo!()
    }
}

pub struct _VP;

impl vc::VP for _VP {
    type Options = ();

    async fn generate<S>(creds: Vec<(Credential, S)>, options: ()) -> Result<Presentation, VCError>
    where
        S: Signer,
    {
        todo!()
    }
}

impl ToCredential for CredentialMaterial {
    async fn to_credential(&self, signer: impl kms::Signer, options: GenerationOptions) -> Result<Credential, VCError> {
        todo!()
    }
}

pub struct _Verifier;

impl vc::Verifier for _Verifier {
    type Options = ();

    async fn validate(presentation: Presentation, options: ()) -> Result<(), VCError> {
        todo!()
    }
}
// exchange::oid4vc

pub struct Issuer
{
    metadata: oid4vc::IssuerMetadata,
    kms: _Kms,
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

    async fn issue_credential(req: oid4vc::CredentialRequest, material: vc::CredentialMaterial, key_id: KeyID) -> Result<Credential, oid4vc::OidError> {
        todo!()
    }
}

