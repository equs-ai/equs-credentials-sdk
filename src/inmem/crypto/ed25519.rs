use crate::crypto;
use crate::crypto::{MalformedSnafu, VerificationSnafu};
use async_trait::async_trait;
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use tracing::{instrument, Level};

#[derive(Debug, Clone)]
pub struct Ed25519 {
    signing_key: SigningKey,
}

impl crypto::SigningKey for Ed25519 {}

impl crypto::VerifyingKey for Ed25519 {}

impl crypto::Suite for Ed25519 {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn gen() -> Vec<u8> {
        let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
        signing_key.to_bytes().to_vec()
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn from_secret(vec: Vec<u8>) -> Result<Ed25519, crypto::Error> {
        let s: SecretKey = vec.try_into().map_err(|_| {
            MalformedSnafu {
                details: "Invalid secret key bytes".to_string(),
            }
            .build()
        })?;
        let signing_key = SigningKey::from_bytes(&s);

        Ok(Ed25519 { signing_key })
    }
}

impl crypto::Key for Ed25519 {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn pub_key(&self) -> Result<Vec<u8>, crypto::Error> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        let pubk = self.pub_key().ok()?;
        let s: &[u8] = &pubk;

        if let Ok(jwk) = ssi::jwk::ed25519_parse(s) {
            Some(jwk)
        } else {
            None
        }
    }
}

#[async_trait]
impl crypto::Signer for Ed25519 {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn alg(&self) -> crypto::Alg {
        crypto::Alg::EdDSA
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
        let signature: Signature = self.signing_key.sign(payload);
        Ok(signature.to_vec())
    }
}

#[async_trait]
impl crypto::Verifier for Ed25519 {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        let signature = Signature::from_slice(signature);

        match signature {
            Ok(sg) => self.signing_key.verify(data, &sg).map_err(|e| {
                VerificationSnafu {
                    details: e.to_string(),
                }
                .build()
            }),
            Err(e) => VerificationSnafu {
                details: e.to_string(),
            }
            .fail(),
        }
    }
}
