use oid4vci::openidconnect;
use serde::{Deserialize, Serialize};

use crate::core_::{crypto, did};
use crate::core_::did::DIDURL;

// VC formats
pub mod jwt_vc_json;
pub mod ldp_vc;
pub mod sd_jwt_vc;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("key not supported")]
    KeyNotSupported,
    #[error("signing error: {0}")]
    Signing(String),
    #[error("verifying error: {0}")]
    Verifying(String),
    #[error("parsing error: {0}")]
    Parsing(String),
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

pub struct VerifyOptions;

pub trait API<CL, C, P, CM, PM>
where
    C: HasClaims<CL>,
    P: HasCredential<C>,
{
    async fn create_vc<S, K>(claims: CL,
                             issuer_data: (&DIDURL, S),
                             holder_data: (&DIDURL, K),
                             metadata: CM) -> Result<C>
    where
        S: crypto::Signer + 'static,
        K: crypto::Key
    ;

    async fn create_vp<S>(credential: &C, signer: S,
                          nonce: Nonce, verifier_id: &str,
                          holder_did_url: &DIDURL, metadata: PM) -> Result<P>
    where
        S: crypto::Signer + 'static
    ;

    async fn verify_vp(presentation: &P, nonce: Nonce, verifier_id: &str, opts: VerifyOptions) -> Result<()>;
}

pub trait HasClaims<CL> {
    fn parse_claims(&self) -> Result<CL>;
}

pub trait HasCredential<C> {
    fn get_credential(&self) -> Result<C>;
}