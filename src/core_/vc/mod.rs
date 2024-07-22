use serde::{Deserialize, Serialize};

use crate::core_::crypto;
use crate::core_::did::DIDURL;

// VC formats
pub mod jwt_vc_json;
pub mod ldp_vc;
pub mod sd_jwt_vc;

#[derive(Debug)]
pub enum Error {}

pub type JWTRaw = String;
pub type Nonce = String;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    async fn create_vc<S>(claims: CL, signer: S, iss_did_url: &DIDURL, metadata: CM) -> Result<C, Error>
    where
        S: crypto::Signer,
    ;

    async fn create_vp<S>(credential: &C, signer: S,
                          nonce: Nonce, verifier_id: &str,
                          holder_did_url: &DIDURL, metadata: PM) -> Result<P, Error>
    where
        S: crypto::Signer
    ;

    async fn verify_vp(presentation: &P, opts: VerifyOptions) -> Result<(), Error>;
}

pub trait HasClaims<CL> {
    fn parse_claims(&self) -> CL;
}

pub trait HasCredential<C> {
    fn get_credential(&self) -> C;
}