use std::fmt;
use std::iter::Map;

use crate::core_::{did, kms};

// Error handling
#[derive(fmt::Debug)]
pub enum VCError {}

// Basic types definitions
pub type W3cVc = ssi::vc::Credential;
pub type W3cVcSubj = ssi::vc::CredentialSubject;
pub type W3pVp = ssi::vc::Presentation;

pub type ISOMdl = String;

pub type JWTRaw = String;

// The material Verifiable Credential could be built from
// Does not and should not yet contain any signatures and proofs
pub enum CredentialMaterial {
    JWT_VC_JSON(W3cVc),
    JWT_VC_JSON_LD(W3cVc),
    LDP_VC(W3cVc),

    VC_SD_JWT(W3cVc),
    ISOMdl(ISOMdl),
    // etc
}

// The resulting signed Verifiable Credential in the target format, serializable
pub enum Credential {
    W3C_LDP(W3cVc),
    W3C_JWT_JSON(JWTRaw),
    W3C_JWT_JSON_LD(JWTRaw),
    SD_JWT(JWTRaw),
    // etc
    ISOMdl(String),
}

impl Credential {
    pub fn subject_did(&self) -> did::DID {
        todo!()
    }
}

pub enum Presentation {
    W3cVp(W3pVp),
    // etc
}

pub enum ProofPreparation {
    JsonLd(ssi::ldp::ProofPreparation),
    // etc
}

pub struct GenerationOptions {}
pub struct ValidationOptions {}

pub trait W3cBuilder {
    fn subject(&self, arg: W3cVcSubj) -> impl W3cBuilder;

    fn subject_from_did(&self, arg: &did::DID) -> impl W3cBuilder;

    fn claims(&self, arg: Map<String, serde_json::Value>) -> impl W3cBuilder;

    fn claims_from_json(&self, arg: serde_json::Value) -> impl W3cBuilder;

    fn build(&self) -> W3cVc;
}

pub trait ToCredential {
    async fn to_credential(&self, signer: impl kms::Signer, options: GenerationOptions) -> Result<Credential, VCError>;
}

pub trait ProofPrepare {
    async fn prepare(&self) -> ProofPreparation;
}

impl ProofPrepare for Credential {
    async fn prepare(&self) -> ProofPreparation {
        todo!()
    }
}

pub trait VC {
    type Options;

    // Type of the resulting Verifiable Credential must be unambiguously inferred from CredentialMaterial
    async fn generate<S, P>(cred: CredentialMaterial, proof_gen: P, signer: S, options: Self::Options) -> Result<Credential, VCError>
    where
        S: kms::Signer,
        P: ProofPrepare
    ;
}

pub trait VP {
    type Options;

    // Assumption: Presentation to contain exactly one Credential
    async fn generate<S>(cred: &Credential, signer: S, options: Self::Options) -> Result<Presentation, VCError>
    where
        S: kms::Signer,
    ;
}

pub trait Verifier {
    type Options;

    async fn validate(presentation: &Presentation, options: Self::Options) -> Result<(), VCError>;
}