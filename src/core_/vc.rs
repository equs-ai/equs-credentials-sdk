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

pub type JWTRaw = String;

pub enum CredentialMaterial {
    W3c(W3cVc),
    // etc
}

pub enum Credential {
    JsonLd(W3cVc),
    JwtVc(JWTRaw),
    // etc
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

    async fn generate<S, P>(cred: CredentialMaterial, proof_gen: P, signer: S, options: Self::Options) -> Result<Credential, VCError>
    where
        S: kms::Signer,
        P: ProofPrepare
    ;
}

pub trait VP {
    type Options;

    async fn generate<S>(creds: Vec<(Credential, S)>, options: Self::Options) -> Result<Presentation, VCError>
    where
        S: kms::Signer,
    ;
}

pub trait Verifier {
    type Options;

    async fn validate(presentation: Presentation, options: Self::Options) -> Result<(), VCError>;
}