use crate::crypto;
use crate::crypto::{
    Alg, BbsParameters, BbsVerifyingParameters, IncorrectKeySnafu, Key, Signer, SigningKey,
    SigningOptions, SigningSnafu, VerificationSnafu, Verifier, VerifyingKey, VerifyingOptions, JWK,
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
    fn gen() -> Vec<u8> {
        let mut rng = rand::rngs::OsRng {};
        ssi::bbs::generate_secret_key(&mut rng).to_bytes().to_vec()
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
