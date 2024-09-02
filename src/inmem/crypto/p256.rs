use async_trait::async_trait;
use p256::ecdsa::signature::{Signer as EcdsaSigner, Verifier as EcdsaVerifier};
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey};
use rand::rngs::OsRng;

use crate::crypto::{
    Alg, Error, Key, KeyGenerationSnafu, Signer, SigningKey, SigningSnafu, Suite,
    VerificationSnafu, Verifier, VerifyingKey
};

#[derive(Clone)]
pub struct P256 {
    signing_key: EcdsaSigningKey,
}

impl SigningKey for P256 {}

impl VerifyingKey for P256 {}

impl Suite for P256 {
    fn gen() -> Vec<u8> {
        let signing_key = EcdsaSigningKey::random(&mut OsRng);
        signing_key.to_bytes().to_vec()
    }

    fn from_secret(vec: Vec<u8>) -> Result<P256, Error> {
        let s: &[u8] = &vec;

        EcdsaSigningKey::from_slice(s)
            .map(|signing_key| P256 { signing_key })
            .map_err(|err| {
                KeyGenerationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}

impl Key for P256 {
    fn pub_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.signing_key.verifying_key().to_sec1_bytes().to_vec())
    }

    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        self.pub_key()
            .ok()
            .and_then(|key| ssi::jwk::p256_parse(&key).ok())
    }
}

#[async_trait]
impl Signer for P256 {
    fn alg(&self) -> Alg {
        Alg::ES256
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.signing_key
            .try_sign(payload)
            .map(|s: EcdsaSignature| s.to_vec())
            .map_err(|err| { SigningSnafu { details: err.to_string() }.build() })
    }
}

#[async_trait]
impl Verifier for P256 {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature = EcdsaSignature::from_slice(signature)
            .map_err(|err| { VerificationSnafu { details: err.to_string(), }.build() })?;

        self.signing_key
            .verifying_key()
            .verify(data, &signature)
            .map_err(|err| VerificationSnafu { details: err.to_string() }.build())
    }
}
