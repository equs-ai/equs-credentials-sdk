use crate::crypto;
use crate::did::DIDURL;
use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;
use oid4vci::proof_of_possession::{ConversionError, ParsingError, VerificationError};
use snafu::{Location, Snafu};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

pub mod jwt_pop;

// Proof of possession formats
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
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

#[derive(Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported proof format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Conversion error at {location}"))]
    Conversion {
        #[snafu(implicit)]
        location: Location,
        source: ConversionError,
    },
    #[snafu(display("Parsing error at {location}"))]
    Parsing {
        #[snafu(implicit)]
        location: Location,
        source: ParsingError,
    },
    #[snafu(display("Verification error at {location}"))]
    Verification {
        #[snafu(implicit)]
        location: Location,
        source: VerificationError,
    },
    #[snafu(display("VC error at {location}"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: ssi::vc::Error,
    },
    #[snafu(display("JWS error at {location}"))]
    JWS {
        source: ssi::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Crypto error at {location}"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

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
pub trait ProofOfPossession<P> {
    async fn generate<S>(
        did_url: &DIDURL,
        key: S,
        nonce: Nonce,
        opts: GenerateOptions,
    ) -> Result<P>
    where
        S: crypto::SigningKey;

    async fn verify(
        proof: P,
        nonce: Nonce,
        opts: VerifyOptions,
    ) -> Result<(DIDURL, Box<dyn crypto::Key>)>;

    fn alg(proof: &P) -> Result<crypto::Alg>;
}
