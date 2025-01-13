use crate::crypto::Alg;
use crate::inmem::crypto::ecdsa::{Ecdsa, HasJWK};
use crate::inmem::crypto::HasAlg;
use bip32::secp256k1;
use tracing::{instrument, Level};

pub type K256 = Ecdsa<secp256k1::Secp256k1>;

impl HasJWK for secp256k1::Secp256k1 {
    #[instrument(level = Level::TRACE, ret())]
    fn jwk(key: Vec<u8>) -> Option<ssi::jwk::JWK> {
        ssi::jwk::secp256k1_parse(&key).ok()
    }
}

impl HasAlg for secp256k1::Secp256k1 {
    fn algorithm() -> Alg {
        Alg::ES256K
    }
}
