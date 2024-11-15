use crate::inmem::crypto::ecdsa::{Ecdsa, HasJWK};
use bip32::secp256k1;
use tracing::{instrument, Level};

pub type K256 = Ecdsa<secp256k1::Secp256k1>;

impl HasJWK for secp256k1::Secp256k1 {
    #[instrument(level = Level::TRACE, ret())]
    fn jwk(key: Vec<u8>) -> Option<ssi::jwk::JWK> {
        ssi::jwk::secp256k1_parse(&key).ok()
    }
}
