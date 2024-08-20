use std::str::FromStr;

use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;
use ssi::did::DIDURL;

use crate::{crypto, did};
use crate::vc::VCFormat;

pub mod sd_jwt_vc;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("format not supported")]
    FormatNotSupported,
    #[error("key not supported")]
    KeyNotSupported,
    #[error("signing error: {0}")]
    Signing(String),
    #[error("verifying error: {0}")]
    Verifying(String),
    #[error("parsing error: {0}")]
    Parsing(String),
    #[error("presentation: {0}")]
    Presentation(String),
    #[error("incorrect claim: {0}")]
    IncorrectClaim(String),

    #[error(transparent)]
    SpruceDID(#[from] ssi::did::Error),
    #[error(transparent)]
    DID(#[from] did::Error),
    #[error(transparent)]
    JWK(#[from] ssi::jwk::Error),
    #[error(transparent)]
    JWS(#[from] ssi::jws::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

pub type Result<T> = core::result::Result<T, Error>;

pub struct VerifyOptions {}

#[async_trait]
pub trait API<CL, C, P, CM, PM, VR>
where
    C: HasClaims<CL>,
    P: HasCredential<C>,
{
    fn resolve_claims(value: &serde_json::Value) -> CL;

    async fn create_vc<S, K>(claims: CL,
                             issuer_data: (&DIDURL, S),
                             holder_data: (&DIDURL, K),
                             metadata: CM) -> Result<C>
    where
        S: crypto::Signer,
        K: crypto::Key,
    ;

    async fn create_vp<S>(credential: &C,
                          holder_data: (&DIDURL, S),
                          nonce: Nonce, verifier_id: &str,
                          metadata: PM) -> Result<P>
    where
        S: crypto::Signer,
    ;

    async fn verify_vp(presentation: &P,
                       nonce: Nonce, verifier_id: &str,
                       opts: VerifyOptions) -> Result<VR>;
}

pub trait HasClaims<CL> {
    fn parse_claims(&self) -> Result<CL>;
}

pub trait HasCredential<C> {
    fn get_credential(&self) -> Result<C>;
}

impl FromStr for VCFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<VCFormat> {
        match s {
            "jwt_vc_json" => Ok(VCFormat::JwtVcJson),
            "jwt_vc_json-ld" => Ok(VCFormat::JwtVcJsonLD),
            "ldp_vc" => Ok(VCFormat::LdpVc),
            "vc+sd-jwt" => Ok(VCFormat::SdJwtVc),
            _ => Err(Error::FormatNotSupported),
        }
    }
}