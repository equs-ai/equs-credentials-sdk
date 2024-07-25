use async_trait::async_trait;
use p256::ecdsa::{Signature, signature, SigningKey};
use p256::ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;

use crate::core_::crypto;

#[derive(Clone)]
pub struct P256 {
    signing_key: SigningKey,
}

impl crypto::SigningKey for P256 {}

impl crypto::VerifyingKey for P256 {}

impl crypto::Suite for P256 {
    fn gen() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut OsRng);
        signing_key.to_bytes().to_vec()
    }

    fn from_secret(vec: Vec<u8>) -> Result<P256, crypto::Error> {
        let s: &[u8] = &vec;

        if let Ok(signing_key) = SigningKey::from_slice(s) {
            Ok(P256 { signing_key })
        } else {
            Err(crypto::Error::KeyGeneration(String::from("invalid format")))
        }
    }
}

impl crypto::Key for P256 {
    fn pub_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        let pubk = self.pub_key();
        let s: &[u8] = &pubk;

        if let Ok(jwk) = ssi::jwk::p256_parse(s) {
            Some(jwk)
        } else {
            None
        }
    }
}

#[async_trait]
impl crypto::Signer for P256 {
    fn alg(&self) -> crypto::Alg {
        crypto::Alg::ES256
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::Error> {
        let sgn: Result<Signature, _> = self.signing_key.try_sign(payload);
        let res = sgn.map(|s| s.to_vec()).map_err(|e| crypto::Error::Signature(e.to_string()));
        res
    }
}

#[async_trait]
impl crypto::Verifier for P256 {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        let verifying_key = &self.signing_key.verifying_key();
        let sgn: Result<Signature, signature::Error> = Signature::from_slice(signature);
        let res: Result<(), crypto::Error> = match sgn {
            Ok(sg) => verifying_key.verify(data, &sg).map_err(|e| crypto::Error::Verification(e.to_string())),
            Err(e) => Err(crypto::Error::Signature(e.to_string())),
        };

        res
    }
}
