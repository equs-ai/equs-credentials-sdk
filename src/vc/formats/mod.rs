use std::fmt::Debug;

use async_trait::async_trait;
use snafu::{Location, Snafu};
use ssi::did::DIDURL;

use crate::nonce::Nonce;
use crate::{crypto, did};
use common_macros::DebugError;

pub mod sd_jwt_vc;
pub mod vc;
pub mod vp;

/// `VC` format internal error.
///
/// Defines errors for all supported low-level VC operations.
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },

    #[snafu(display("Unsupported key type: {type_}"))]
    KeyTypeNotSupported { type_: String },

    #[snafu(display("Signing error at {location}\n Cause: {details}"))]
    Signing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Verification error at {location}\n Cause: {details}"))]
    Verifying {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Parsing error at {location}\n Cause: {details}"))]
    Parsing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Presentation error at {location}\n Cause: {details}"))]
    Presentation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DID error at {location}"))]
    SpruceDID {
        source: ssi::did::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DID error at {location}"))]
    DID {
        source: did::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("JWK error at {location}"))]
    JWK {
        source: ssi::jwk::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("JWS error at {location}"))]
    JWS {
        source: ssi::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("JSON error at {location}"))]
    Json {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Base64 decoding error at {location}"))]
    Base64 {
        source: base64::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct VerifyOptions {}

#[async_trait]
pub trait API<CL, C, P, CM, PM, VR>
where
    C: HasClaims<CL>,
    P: HasCredential<C>,
{
    fn resolve_claims(value: &serde_json::Value) -> CL;

    async fn create_vc<S, K>(
        claims: CL,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: CM,
    ) -> Result<C>
    where
        S: crypto::Signer,
        K: crypto::Key;

    async fn create_vp<S>(
        credential: &C,
        holder_signer: S,
        nonce: &Nonce,
        verifier_id: &str,
        metadata: PM,
    ) -> Result<P>
    where
        S: crypto::Signer;

    async fn verify_vc(credential: &C, opts: VerifyOptions) -> Result<()>;

    async fn verify_vp(
        presentation: &P,
        nonce: &Nonce,
        verifier_id: &str,
        opts: VerifyOptions,
    ) -> Result<VR>;
}

pub trait HasClaims<CL> {
    fn parse_claims(&self) -> Result<CL>;
}

pub trait HasCredential<C> {
    fn get_credential(&self) -> Result<C>;
}
