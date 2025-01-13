use crate::crypto;
use crate::did::DIDURL;
use crate::nonce::Nonce;
use async_trait::async_trait;
use common_macros::DebugError;
use oid4vci::proof_of_possession::{ConversionError, ParsingError, VerificationError};
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use ssi::dids::DIDURLBuf;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

pub mod jwt_pop;

// Proof of possession formats
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Format {
    Jwt,
    Ldp,
    Cwt,
}

impl From<&Format> for &'static str {
    fn from(value: &Format) -> Self {
        match value {
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
            _ => FormatNotSupportedSnafu { format: s }.fail(),
        }
    }
}

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: &str = self.into();
        write!(f, "{}", str)
    }
}

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported proof format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Unsupported key type: {type_}"))]
    KeyTypeNotSupported { type_: String },
    #[snafu(display("Verification method not found"))]
    VerificationMethodNotFound,
    #[snafu(display("Conversion error"))]
    Conversion {
        #[snafu(implicit)]
        location: Location,
        source: ConversionError,
    },
    #[snafu(display("Parsing error"))]
    Parsing {
        #[snafu(implicit)]
        location: Location,
        source: ParsingError,
    },
    #[snafu(display("Verification error"))]
    Verification {
        #[snafu(implicit)]
        location: Location,
        source: VerificationError,
    },
    #[snafu(display("VC error"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: ssi::claims::vc::v1::JwtVpDecodeError,
    },
    #[snafu(display("JWS error"))]
    JWS {
        source: ssi::claims::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Crypto error"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
    #[snafu(display("Did url error {details}"))]
    DidUrl {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct GenerateOptions {
    pub audience: String,
    pub issuer: Option<String>,
    pub lifetime: Option<time::Duration>,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct VerifyOptions {
    pub audience: String,
    pub issuer: Option<String>,
    pub clock_tolerance: Option<time::Duration>,
}

#[async_trait]
pub trait ProofOfPossession<P> {
    async fn generate<S>(
        did_url: &DIDURL,
        key: S,
        nonce: &Nonce,
        opts: GenerateOptions,
    ) -> Result<P>
    where
        S: crypto::SigningKey;

    async fn verify(
        proof: P,
        nonce: &Nonce,
        opts: VerifyOptions,
    ) -> Result<(DIDURLBuf, Box<dyn crypto::Key>)>;

    fn alg(proof: &P) -> Result<crypto::Alg>;
}
