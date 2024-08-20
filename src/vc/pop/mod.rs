use std::str::FromStr;

use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;

use crate::crypto;
use crate::did::DIDURL;

pub mod jwt_pop;

// Proof of possession formats
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum Format {
    Jwt,
    Ldp,
    Cwt,
}

impl Into<&'static str> for Format {
    fn into(self) -> &'static str {
        match self {
            Format::Jwt => "jwt",
            Format::Ldp => "ldp",
            Format::Cwt => "cwt",
        }
    }
}


impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Format> {
        match s {
            "jwt" => Ok(Format::Jwt),
            "ldp" => Ok(Format::Ldp),
            "cwt" => Ok(Format::Cwt),
            _ => Err(Error::FormatNotSupported),
        }
    }
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("format not supported")]
    FormatNotSupported,
    #[error("conversion error: {0}")]
    Conversion(String),
    #[error("parsing error: {0}")]
    Parsing(String),
    #[error("verification error: {0}")]
    Verification(String),

    #[error(transparent)]
    SpruceVC(#[from] ssi::vc::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

pub trait Proof {
    fn parse(str: &str) -> Result<Self>
    where
        Self: Sized;
}

impl Proof for String {
    fn parse(str: &str) -> Result<Self> {
        Ok(str.to_owned())
    }
}

impl Proof for ssi::vc::Presentation {
    fn parse(str: &str) -> Result<Self> {
        Ok(ssi::vc::Presentation::from_json(str)?)
    }
}

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

#[async_trait]
pub trait ProofOfPossession<P>
where
    P: Proof,
{
    async fn generate<S>(did_url: &DIDURL, key: S, nonce: Nonce, opts: GenerateOptions) -> Result<P>
    where
        S: crypto::SigningKey,
    ;

    async fn verify(proof: P, nonce: Nonce, opts: VerifyOptions) -> Result<(DIDURL, Box<dyn crypto::Key>)>;
}