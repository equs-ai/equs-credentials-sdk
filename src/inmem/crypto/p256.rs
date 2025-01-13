use crate::crypto::Alg;
use crate::inmem::crypto::ecdsa::{Ecdsa, HasJWK};
use crate::inmem::crypto::HasAlg;
use tracing::{instrument, Level};

pub type P256 = Ecdsa<p256::NistP256>;

impl HasJWK for p256::NistP256 {
    #[instrument(level = Level::TRACE, ret())]
    fn jwk(key: Vec<u8>) -> Option<ssi::jwk::JWK> {
        ssi::jwk::p256_parse(&key).ok()
    }
}

impl HasAlg for p256::NistP256 {
    fn algorithm() -> Alg {
        Alg::ES256
    }
}
