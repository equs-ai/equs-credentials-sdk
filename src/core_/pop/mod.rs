use crate::core_::crypto;
use crate::core_::did::DIDURL;
use crate::core_::vc::{Error, Nonce};

// Proof of possession formats
pub mod jwt_pop;
pub mod ldp_pop;

pub trait Proof {}

pub struct VerifyOptions;

pub trait ProofOfPossession<P>
where
    P: Proof,
{
    async fn generate<S>(did_url: &DIDURL, signer: S, nonce: Nonce, aud: String, iss: Option<String>) -> Result<P, Error>
    where
        S: crypto::Signer
    ;

    async fn verify(proof: P, opts: VerifyOptions) -> Result<(), Error>;
}