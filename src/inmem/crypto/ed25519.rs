use crate::crypto;
use crate::crypto::{MalformedSnafu, VerificationSnafu};
use async_trait::async_trait;
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey};
use ssi::crypto::rand::rngs::OsRng;
use tracing::{Level, instrument};

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
    fn generate() -> Vec<u8> {
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
        ssi::jwk::ed25519_parse(&pubk).ok()
    }

    fn private_key(&self) -> crypto::Result<Vec<u8>> {
        Ok(self.signing_key.as_bytes().as_slice().to_vec())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Key, Signer, Suite, Verifier};
    use rstest::rstest;

    fn fresh() -> Ed25519 {
        Ed25519::from_secret(Ed25519::generate()).unwrap()
    }

    #[test]
    fn generate_returns_32_byte_secret() {
        assert_eq!(Ed25519::generate().len(), 32);
    }

    #[test]
    fn generate_returns_distinct_secrets_on_each_call() {
        assert_ne!(Ed25519::generate(), Ed25519::generate());
    }

    #[test]
    fn from_secret_roundtrips_valid_32_byte_input() {
        let bytes = Ed25519::generate();
        let suite = Ed25519::from_secret(bytes.clone()).unwrap();

        assert_eq!(suite.private_key().unwrap(), bytes);
    }

    #[rstest]
    #[case::empty(vec![])]
    #[case::too_short(vec![0u8; 16])]
    #[case::too_long(vec![0u8; 64])]
    #[should_panic(expected = "Invalid secret key bytes")]
    fn from_secret_rejects_wrong_length(#[case] bytes: Vec<u8>) {
        Ed25519::from_secret(bytes).unwrap();
    }

    #[test]
    fn pub_key_returns_32_byte_compressed_point() {
        let suite = fresh();

        assert_eq!(suite.pub_key().unwrap().len(), 32);
    }

    #[test]
    fn pub_key_is_deterministic_for_same_secret() {
        let secret = Ed25519::generate();
        let a = Ed25519::from_secret(secret.clone()).unwrap();
        let b = Ed25519::from_secret(secret).unwrap();

        assert_eq!(a.pub_key().unwrap(), b.pub_key().unwrap());
    }

    #[test]
    fn jwk_returns_some_ed25519_for_valid_key() {
        let suite = fresh();
        let jwk = suite.jwk().unwrap();

        assert_eq!(
            crate::utils::jwk::get_key_type(&jwk),
            Some(crate::kms::KeyType::Ed25519)
        );
    }

    #[test]
    fn private_key_returns_original_secret_bytes() {
        let bytes = Ed25519::generate();
        let suite = Ed25519::from_secret(bytes.clone()).unwrap();

        assert_eq!(suite.private_key().unwrap(), bytes);
    }

    #[tokio::test]
    async fn sign_then_verify_succeeds_on_same_payload() {
        let suite = fresh();
        let msg = b"the quick brown fox";

        let sig = suite.sign(msg).await.unwrap();
        suite.verify(msg, &sig).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Verification error")]
    async fn verify_rejects_tampered_payload() {
        let suite = fresh();
        let sig = suite.sign(b"original").await.unwrap();

        suite.verify(b"tampered", &sig).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Verification error")]
    async fn verify_rejects_malformed_signature_bytes() {
        let suite = fresh();

        suite.verify(b"data", &[0u8; 8]).await.unwrap();
    }
}
