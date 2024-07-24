use crate::core_::crypto;
use crate::core_::did::DIDURL;
use crate::core_::vc::Nonce;

// Proof of possession formats
pub mod jwt_pop;
pub mod ldp_pop;

#[derive(Debug, Clone, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("conversion error: {0}")]
    Conversion(String),
    #[error("parsing error: {0}")]
    Parsing(String),
    #[error("verification error: {0}")]
    Verification(String),
}

pub trait Proof {}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct GenerateOptions {
    pub cred_iss_id: String,
    pub client_id: Option<String>,
    pub lifetime: Option<time::Duration>,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct VerifyOptions {
    pub cred_iss_id: String,
    pub client_id: Option<String>,
}

pub trait ProofOfPossession<P>
where
    P: Proof,
{
    async fn generate<S>(did_url: &DIDURL, key: S, nonce: Nonce, opts: GenerateOptions) -> Result<P, Error>
    where
        S: crypto::SigningKey + 'static
    ;

    async fn verify(proof: P, nonce: Nonce, opts: VerifyOptions) -> Result<(), Error>;
}