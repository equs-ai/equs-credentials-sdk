use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey};
use rand::rngs::OsRng;

use crate::core_::crypto;
use crate::core_::crypto::Key;

#[derive(Clone)]
pub struct Ed25519 {
    signing_key: SigningKey,
}

impl crypto::Suite for Ed25519 {
    fn gen() -> Vec<u8> {
        let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
        signing_key.to_bytes().to_vec()
    }

    fn from_secret(vec: Vec<u8>) -> Result<Ed25519, crypto::Error> {
        let s: SecretKey = vec.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&s);

        Ok(Ed25519 { signing_key })
    }
}

impl Key for Ed25519 {
    fn pub_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        let pubk = self.pub_key();
        let s: &[u8] = &pubk;

        if let Ok(jwk) = ssi::jwk::ed25519_parse(s) {
            Some(jwk)
        } else {
            None
        }
    }
}

impl crypto::Signer for Ed25519 {
    fn alg(&self) -> crypto::Alg {
        crypto::Alg::ED25519
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::Error> {
        let signature: Signature = self.signing_key.sign(payload);
        Ok(signature.to_vec())
    }
}

impl crypto::Verifier for Ed25519 {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        let sgn = Signature::from_slice(signature);
        let res: Result<(), crypto::Error> = match sgn {
            Ok(sg) => self.signing_key.verify(data, &sg).map_err(|e| crypto::Error::Signature(e)),
            Err(e) => Err(crypto::Error::Verification(e)),
        };

        res
    }
}
