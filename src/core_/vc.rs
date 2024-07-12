use std::iter::Map;
use crate::core_::kms;

// Error handling
pub enum VCError {}

// Basic types definitions
pub type Credential = ssi::vc::Credential;
pub type CredentialSubject = ssi::vc::CredentialSubject;

pub type Presentation = ssi::vc::Presentation;

pub enum VCFormat {
    JwtVc,
    JsonLd,
    //etc
}

pub struct GenerationOptions {}
pub struct ValidationOptions {}

pub struct CredentialMaterial {
    format: VCFormat,
    subject: CredentialSubject,
    claims: Map<String, serde_json::Value>,
    // etc
}

pub trait ToCredential {
    async fn to_credential(&self, signer: impl kms::Signer, options: GenerationOptions) -> Result<Credential, VCError>;
}

pub trait KmsObservable<KH> {
    async fn key_handle(&self, kms: impl kms::Kms<KH>) -> Result<KH, VCError>;
}

pub trait VC {
    async fn generate<KH: kms::KeyHandle>(material: CredentialMaterial, kh: KH, options: GenerationOptions) -> Result<Credential, VCError>;
}

pub trait VP {
    async fn generate<KH: kms::KeyHandle>(creds: Vec<(Credential, KH)>) -> Result<Presentation, VCError>;
}

pub trait Verifier {
    async fn validate(presentation: Presentation, options: ValidationOptions) -> Result<(), VCError>;
}