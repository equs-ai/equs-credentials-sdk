use crate::crypto::Alg;

pub mod bip32;
pub mod ed25519;

pub(crate) mod ecdsa;
pub mod k256;
pub mod p256;

pub trait HasAlg {
    fn algorithm() -> Alg;
}
