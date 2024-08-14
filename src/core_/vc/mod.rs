use std::fmt::{Display, Formatter};
use std::str::FromStr;
use async_trait::async_trait;
use oid4vci::openidconnect;
use serde::{Deserialize, Serialize};

use crate::core_::{crypto, did};
use crate::core_::did::DIDURL;

pub const JWT_VC_JSON: &str = "jwt_vc_json";
pub const JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
pub const LDP_VC: &str = "ldp_vc";
pub const SD_JWT_VC: &str = "vc+sd-jwt";
pub const JWT_VP: &str = "jwt_vp";
pub const LDP_VP: &str = "ldp_vp";

// VC formats
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
}

impl Into<&'static str> for &VCFormat {
    fn into(self) -> &'static str {
        match self {
            VCFormat::JwtVcJson => JWT_VC_JSON,
            VCFormat::JwtVcJsonLD => JWT_VC_JSON_LD,
            VCFormat::LdpVc => LDP_VC,
            VCFormat::SdJwtVc => SD_JWT_VC,
        }
    }
}

impl Display for VCFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: &str = self.into();
        write!(f, "{}", str)
    }
}

impl FromStr for VCFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<VCFormat> {
        match s {
            JWT_VC_JSON => Ok(VCFormat::JwtVcJson),
            JWT_VC_JSON_LD => Ok(VCFormat::JwtVcJsonLD),
            LDP_VC => Ok(VCFormat::LdpVc),
            SD_JWT_VC => Ok(VCFormat::SdJwtVc),
            _ => Err(Error::FormatNotSupported),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum VPFormat {
    JwtVp,
    LdpVp,
}

impl Into<&'static str> for VPFormat {
    fn into(self) -> &'static str {
        match self {
            VPFormat::JwtVp => JWT_VP,
            VPFormat::LdpVp => LDP_VP,
        }
    }
}

pub mod jwt_vc_json;
pub mod ldp_vc;
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

pub type JWTRaw = String;
pub type Nonce = openidconnect::Nonce;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Credential {
    // W3C
    JwtVcJson(jwt_vc_json::Credential),
    JwtVcJsonLd(jwt_vc_json::Credential),
    LdpVc(ldp_vc::Credential),
    // SD-JWT
    SdJwt(sd_jwt_vc::Credential),
    // etc
    // ISOMdl(String),
}

impl Credential {
    pub fn format(&self) -> VCFormat {
        match self {
            Credential::JwtVcJson(_) => VCFormat::JwtVcJson,
            Credential::JwtVcJsonLd(_) => VCFormat::JwtVcJsonLD,
            Credential::LdpVc(_) => VCFormat::LdpVc,
            Credential::SdJwt(_) => VCFormat::SdJwtVc,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub format: VCFormat,
    pub alg: crypto::Alg,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Presentation {
    // W3C
    JwtVp(jwt_vc_json::Presentation),
    LdpVp(ldp_vc::Presentation),
    // SD-JWT
    SdJwtVp(sd_jwt_vc::Presentation),
}

pub struct VerifyOptions;

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
        S: crypto::Signer + 'static,
        K: crypto::Key,
    ;

    async fn create_vp<S>(credential: &C,
                          holder_data: (&DIDURL, S),
                          nonce: Nonce, verifier_id: &str,
                          metadata: PM) -> Result<P>
    where
        S: crypto::Signer + 'static
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