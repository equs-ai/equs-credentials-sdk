use crate::crypto;
use crate::crypto::{
    Alg, BbsParameters, BbsVerifyingParameters, IncorrectKeySnafu, JWK, Key, Signer, SigningKey,
    SigningOptions, SigningSnafu, VerificationSnafu, Verifier, VerifyingKey, VerifyingOptions,
};
use async_trait::async_trait;
use ssi::bbs::BBSplusSecretKey;
use zkryptium::bbsplus::ciphersuites::Bls12381Sha256;
use zkryptium::bbsplus::commitment::BlindFactor;
use zkryptium::bbsplus::signature::BBSplusSignature;
use zkryptium::schemes::algorithms::BBSplus;
use zkryptium::schemes::generics::{BlindSignature, Signature};

#[derive(Clone)]
pub struct Bls12381(BBSplusSecretKey);

impl SigningKey for Bls12381 {}

impl Key for Bls12381 {
    fn pub_key(&self) -> crypto::Result<Vec<u8>> {
        let pub_key_bytes = self.0.public_key().to_bytes().to_vec();

        Ok(pub_key_bytes)
    }

    fn jwk(&self) -> Option<JWK> {
        let jwk: ssi::jwk::JWK = self.0.public_key().into();

        Some(jwk)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for Bls12381 {
    fn alg(&self) -> Alg {
        Alg::BBS
    }

    async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
        self.sign_multi(&[payload.to_vec()], None).await
    }

    async fn sign_multi(
        &self,
        payloads: &[Vec<u8>],
        opts: Option<SigningOptions>,
    ) -> crypto::Result<Vec<u8>> {
        let params = match opts {
            Some(SigningOptions::BBS(params)) => params,
            _ => BbsParameters::Baseline { header: [0; 64] },
        };

        ssi::bbs::sign(params, &self.0, &self.0.public_key(), payloads).map_err(|err| {
            SigningSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

impl VerifyingKey for Bls12381 {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Verifier for Bls12381 {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> crypto::Result<()> {
        self.verify_multi(&[data.to_vec()], signature, None).await
    }

    async fn verify_multi(
        &self,
        data: &[Vec<u8>],
        signature: &[u8],
        opts: Option<VerifyingOptions>,
    ) -> crypto::Result<()> {
        let params = match opts {
            Some(VerifyingOptions::BBS(params)) => params,
            _ => BbsVerifyingParameters::Baseline { header: [0; 64] },
        };

        let signature: &[u8; BBSplusSignature::BYTES] = signature.try_into().map_err(|_| {
            VerificationSnafu {
                details: "Incorrect signature",
            }
            .build()
        })?;

        match params {
            BbsVerifyingParameters::Baseline { header } => {
                let signature = Signature::<BBSplus<Bls12381Sha256>>::from_bytes(signature)
                    .map_err(|err| {
                        VerificationSnafu {
                            details: err.to_string(),
                        }
                        .build()
                    })?;

                signature
                    .verify(&self.0.public_key(), Some(data), Some(&header))
                    .map_err(|err| {
                        VerificationSnafu {
                            details: err.to_string(),
                        }
                        .build()
                    })
            }
            BbsVerifyingParameters::Blind {
                header,
                committed_messages,
                secret_prover_blind,
                signer_blind,
            } => {
                let signature = BlindSignature::<BBSplus<Bls12381Sha256>>::from_bytes(signature)
                    .map_err(|err| {
                        VerificationSnafu {
                            details: err.to_string(),
                        }
                        .build()
                    })?;

                let secret_prover_blind =
                    secret_prover_blind.map(|b| BlindFactor::from_bytes(&b).unwrap());
                let signer_blind = signer_blind.map(|b| BlindFactor::from_bytes(&b).unwrap());

                signature
                    .verify(
                        &self.0.public_key(),
                        Some(&header),
                        Some(data),
                        committed_messages.as_deref(),
                        secret_prover_blind.as_ref(),
                        signer_blind.as_ref(),
                    )
                    .map_err(|err| {
                        VerificationSnafu {
                            details: err.to_string(),
                        }
                        .build()
                    })
            }
        }
    }
}

impl crypto::Suite for Bls12381 {
    fn generate() -> Vec<u8> {
        ssi::bbs::generate_secret_key(&mut ssi::crypto::rand::rngs::OsRng {})
            .to_bytes()
            .to_vec()
    }

    fn from_secret(bytes: Vec<u8>) -> crypto::Result<Self> {
        BBSplusSecretKey::from_bytes(&bytes)
            .map_err(|err| {
                IncorrectKeySnafu {
                    details: err.to_string(),
                }
                .build()
            })
            .map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{BbsVerifyingParameters, Suite};

    fn fresh() -> Bls12381 {
        Bls12381::from_secret(Bls12381::generate()).unwrap()
    }

    #[test]
    fn generate_returns_non_empty_secret() {
        assert!(!Bls12381::generate().is_empty());
    }

    #[test]
    fn generate_returns_distinct_secrets_each_call() {
        assert_ne!(Bls12381::generate(), Bls12381::generate());
    }

    #[test]
    fn from_secret_accepts_generated_bytes() {
        let bytes = Bls12381::generate();
        let suite = Bls12381::from_secret(bytes.clone()).unwrap();

        // Confirm the wrapped secret round-trips to the same public key as
        // building the secret directly from the same bytes.
        let other = Bls12381::from_secret(bytes).unwrap();
        assert_eq!(suite.pub_key().unwrap(), other.pub_key().unwrap());
    }

    #[test]
    #[should_panic(expected = "Incorrect key")]
    fn from_secret_rejects_malformed_bytes() {
        Bls12381::from_secret(vec![0xFF; 5]).unwrap();
    }

    #[test]
    fn pub_key_returns_non_empty_bytes() {
        let suite = fresh();

        assert!(!suite.pub_key().unwrap().is_empty());
    }

    #[test]
    fn jwk_returns_some_for_valid_key() {
        let suite = fresh();

        assert!(suite.jwk().is_some());
    }

    #[tokio::test]
    async fn sign_delegates_to_sign_multi_with_baseline_defaults() {
        let suite = fresh();

        let sig = suite.sign(b"payload").await.unwrap();

        // The default sign() path uses baseline params; verify() does the same.
        suite.verify(b"payload", &sig).await.unwrap();
    }

    #[tokio::test]
    async fn sign_multi_baseline_signs_then_verifies_multi_payloads() {
        let suite = fresh();
        let payloads = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];

        let sig = suite.sign_multi(&payloads, None).await.unwrap();
        suite.verify_multi(&payloads, &sig, None).await.unwrap();
    }

    #[tokio::test]
    async fn sign_multi_baseline_with_custom_header_roundtrips() {
        let suite = fresh();
        let payloads = vec![b"x".to_vec()];
        let sign_opts = Some(crate::crypto::SigningOptions::BBS(
            BbsParameters::Baseline { header: [7u8; 64] },
        ));
        let verify_opts = Some(crate::crypto::VerifyingOptions::BBS(
            BbsVerifyingParameters::Baseline { header: [7u8; 64] },
        ));

        let sig = suite.sign_multi(&payloads, sign_opts).await.unwrap();
        suite
            .verify_multi(&payloads, &sig, verify_opts)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Verification error")]
    async fn verify_multi_rejects_tampered_payload() {
        let suite = fresh();
        let original = vec![b"hello".to_vec()];
        let sig = suite.sign_multi(&original, None).await.unwrap();

        let tampered = vec![b"world".to_vec()];
        suite.verify_multi(&tampered, &sig, None).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Verification error")]
    async fn verify_multi_rejects_malformed_signature_bytes() {
        let suite = fresh();

        suite
            .verify_multi(&[b"data".to_vec()], &[0u8; 4], None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Verification error")]
    async fn verify_multi_rejects_header_mismatch() {
        let suite = fresh();
        let payloads = vec![b"msg".to_vec()];

        // Sign with one header, verify with a different header.
        let sign_opts = Some(crate::crypto::SigningOptions::BBS(
            BbsParameters::Baseline { header: [1u8; 64] },
        ));
        let verify_opts = Some(crate::crypto::VerifyingOptions::BBS(
            BbsVerifyingParameters::Baseline { header: [2u8; 64] },
        ));

        let sig = suite.sign_multi(&payloads, sign_opts).await.unwrap();
        suite
            .verify_multi(&payloads, &sig, verify_opts)
            .await
            .unwrap();
    }
}
