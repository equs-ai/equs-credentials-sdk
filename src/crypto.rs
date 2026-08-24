//! APIs for implementing cryptographic primitives.

use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use ssi::jwk;
use std::fmt::Debug;
use std::ops::Deref;
use std::str::FromStr;
use strum_macros::{Display, IntoStaticStr};

/// `Result` alias for Crypto-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// JSON Web Key
pub type JWK = jwk::JWK;

pub type ProtocolAlg = jwk::algorithm::Algorithm;

/// Enumerates general errors encountered during `Crypto` operations.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported key type: {type_}"))]
    KeyNotSupported { type_: String },
    #[snafu(display("Unsupported algorithm: {alg}"))]
    AlgNotSupported { alg: String },
    #[snafu(display("Signing error: {details}"))]
    Signing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Verification error: {details}"))]
    Verification {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Key generation error: {details}"))]
    KeyGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Incorrect key: {details}"))]
    IncorrectKey {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Derivation not supported for: {kid}"))]
    DerivationNotSupported { kid: String },
    #[snafu(display("Derivation error: {details}"))]
    Derivation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Malformed error: {details}"))]
    Malformed {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

/// Enum with supported `Crypto` algorithms.
///
/// *NOTE*: more algs to be supported later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, IntoStaticStr)]
#[non_exhaustive]
pub enum Alg {
    ES256,
    ES256K,
    EdDSA,
    BBS,
}

/// Parameters for BBS signature schemes.
pub type BbsParameters = ssi::crypto::algorithm::BbsParameters;

/// Additional signing options
#[derive(Debug, Clone, Display)]
#[non_exhaustive]
pub enum SigningOptions {
    BBS(BbsParameters),
}

/// Parameters for BBS Signature verification
pub enum BbsVerifyingParameters {
    Baseline {
        header: [u8; 64],
    },
    Blind {
        header: [u8; 64],
        committed_messages: Option<Vec<Vec<u8>>>,
        secret_prover_blind: Option<[u8; 32]>,
        signer_blind: Option<[u8; 32]>,
    },
}

/// Additional verifying options
pub enum VerifyingOptions {
    BBS(BbsVerifyingParameters),
}

/// An async `Signer` interface.
///
/// Exposes primitives to sign a binary payload.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Signer: WasmNotSync + WasmNotSend {
    /// Returns algorithm of the signer.
    ///
    /// # Returns
    ///
    /// An `Alg` enum value.
    fn alg(&self) -> Alg;

    /// Sign the provided binary payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - a slice of bytes to be signed.
    ///
    /// # Returns
    ///
    /// A signed `payload` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Signing] - fails to sign a payload.
    /// * [Error::AlgNotSupported] - algorithm is not supported.
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>>;

    /// Signs multiple binary payloads in a batch using multi signing.
    ///
    /// # Arguments
    ///
    /// * `payloads` - a slice of `Vec<u8>`, where each element represents a message to be signed.
    /// * `opts` - extra signing options.
    ///
    /// # Returns
    ///
    /// A signed `payload` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Signing] - ails to sign a payload.
    /// * [Error::AlgNotSupported] - algorithm is not supported.
    async fn sign_multi(
        &self,
        payloads: &[Vec<u8>],
        opts: Option<SigningOptions>,
    ) -> Result<Vec<u8>> {
        AlgNotSupportedSnafu {
            alg: self.alg().to_string(),
        }
        .fail()
    }
}

/// An async `Verifier` interface.
///
/// Exposes primitives to verify that a binary data was correctly signed.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Verifier: WasmNotSync + WasmNotSend {
    /// Verify that a signed data was signed using the provided signature.
    ///
    /// # Arguments
    ///
    /// * `data` - a payload to be verified against the signature.
    /// * `signature` - the corresponding signature.
    ///
    /// # Errors
    ///
    /// * [Error::Verification] - verification failed.
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()>;

    /// Verifies an array of data were signed using the given signature (Multi-Signature).
    ///
    /// # Arguments
    ///
    /// * `data` - an array of payload to be verified against the signature.
    /// * `signature` - the corresponding signature.
    /// * `opts` - extra verifying options.
    ///
    /// # Errors
    ///
    /// * [Error::Verification] - verification failed.
    async fn verify_multi(
        &self,
        data: &[Vec<u8>],
        signature: &[u8],
        opts: Option<VerifyingOptions>,
    ) -> Result<()> {
        VerificationSnafu {
            details: "Multi-signature is not supported by this Verifier",
        }
        .fail()
    }
}

/// A general `Key` interface.
///
/// Exposes the public key and the JWK if suitable.
pub trait Key: WasmNotSync + WasmNotSend {
    /// Returns the public key for the corresponding handle.
    ///
    /// # Returns
    ///
    /// Public key bytes.
    ///
    /// # Errors
    ///
    /// * [Error::KeyNotSupported] - key is not supported.
    fn pub_key(&self) -> Result<Vec<u8>>;

    /// Returns the public key in JWK form if it's supported.
    ///
    /// # Returns
    ///
    /// `Some(jwk)` if the public key can be represented as JWK.
    /// `None` if the JWK-form is not supported.
    fn jwk(&self) -> Option<JWK>;

    /// Returns the private key if no errors.
    ///
    fn private_key(&self) -> Result<Vec<u8>> {
        Err(Error::KeyNotSupported {
            type_: "Unimplemented key".to_string(),
        })
    }
}

impl Key for Box<dyn Key> {
    fn pub_key(&self) -> Result<Vec<u8>> {
        self.deref().pub_key()
    }

    fn jwk(&self) -> Option<JWK> {
        self.deref().jwk()
    }
}

/// Utility trait that combines [Signer] and [Key].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SigningKey: Key + Signer {}

/// Utility trait that combines [Verifier] and [Key].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait VerifyingKey: Key + Verifier {}

/// A crypto `Suite` with support of signing/verification.
///
/// Supports extra methods to generate key material.
pub trait Suite: SigningKey + VerifyingKey + Sized {
    /// Generate a private key.
    ///
    /// # Returns
    ///
    /// Private key bytes.
    fn generate() -> Vec<u8>;

    /// Build a `Suite` from a secret key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - private key bytes.
    ///
    /// # Returns
    ///
    /// A `Suite` for the provided key.
    ///
    /// # Errors
    ///
    /// * [Error::IncorrectKey] - wrong key bytes provided
    fn from_secret(bytes: Vec<u8>) -> Result<Self>;
}

impl FromStr for Alg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Alg> {
        match s {
            "ES256" => Ok(Alg::ES256),
            "ES256K" => Ok(Alg::ES256K),
            "EdDSA" => Ok(Alg::EdDSA),
            _ => AlgNotSupportedSnafu { alg: s }.fail(),
        }
    }
}

impl TryFrom<&jwk::Algorithm> for Alg {
    type Error = Error;

    fn try_from(value: &jwk::Algorithm) -> Result<Alg> {
        match value {
            jwk::Algorithm::EdDSA => Ok(Alg::EdDSA),
            jwk::Algorithm::ES256 => Ok(Alg::ES256),
            jwk::Algorithm::ES256K => Ok(Alg::ES256K),
            _ => AlgNotSupportedSnafu {
                alg: serde_json::to_string(value).unwrap_or(format!("{:?}", value)),
            }
            .fail(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rstest::rstest;
    use ssi::jwk;
    use std::str::FromStr;

    #[rstest]
    #[case("ES256", Alg::ES256)]
    #[case("EdDSA", Alg::EdDSA)]
    #[case("ES256K", Alg::ES256K)]
    fn alg_from_str_parses_supported(#[case] input: &str, #[case] expected: Alg) {
        assert_eq!(Alg::from_str(input).unwrap(), expected);
    }

    #[test]
    #[should_panic(expected = "Unsupported algorithm: RS256")]
    fn alg_from_str_rejects_unknown_algorithm() {
        Alg::from_str("RS256").unwrap();
    }

    #[rstest]
    #[case(jwk::Algorithm::ES256, Alg::ES256)]
    #[case(jwk::Algorithm::ES256K, Alg::ES256K)]
    #[case(jwk::Algorithm::EdDSA, Alg::EdDSA)]
    fn alg_try_from_jwk_algorithm_parses_supported(
        #[case] input: jwk::Algorithm,
        #[case] expected: Alg,
    ) {
        assert_eq!(Alg::try_from(&input).unwrap(), expected);
    }

    #[test]
    #[should_panic(expected = "Unsupported algorithm")]
    fn alg_try_from_jwk_algorithm_rejects_unsupported() {
        Alg::try_from(&jwk::Algorithm::None).unwrap();
    }

    struct DummyKey {
        pub_bytes: Vec<u8>,
        jwk_value: Option<JWK>,
    }

    impl Key for DummyKey {
        fn pub_key(&self) -> Result<Vec<u8>> {
            Ok(self.pub_bytes.clone())
        }

        fn jwk(&self) -> Option<JWK> {
            self.jwk_value.clone()
        }
    }

    #[test]
    fn box_dyn_key_pub_key_delegates_to_inner() {
        let inner = DummyKey {
            pub_bytes: vec![1, 2, 3, 4, 5],
            jwk_value: None,
        };
        let boxed: Box<dyn Key> = Box::new(inner);

        assert_eq!(boxed.pub_key().unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn box_dyn_key_jwk_delegates_to_inner() {
        let jwk = jwk::JWK::generate_ed25519().unwrap();
        let inner = DummyKey {
            pub_bytes: vec![],
            jwk_value: Some(jwk.clone()),
        };
        let boxed: Box<dyn Key> = Box::new(inner);

        let returned = boxed.jwk().expect("jwk should be Some");
        assert!(returned.equals_public(&jwk));
    }

    struct OnlySigner;

    #[async_trait]
    impl Signer for OnlySigner {
        fn alg(&self) -> Alg {
            Alg::ES256
        }

        async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported algorithm: ES256")]
    async fn signer_sign_multi_default_returns_alg_not_supported() {
        let signer = OnlySigner;

        signer.sign_multi(&[vec![1]], None).await.unwrap();
    }

    struct OnlyVerifier;

    #[async_trait]
    impl Verifier for OnlyVerifier {
        async fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    #[should_panic(expected = "Multi-signature is not supported")]
    async fn verifier_verify_multi_default_returns_verification_error() {
        let verifier = OnlyVerifier;

        verifier.verify_multi(&[vec![1]], &[2], None).await.unwrap();
    }
}
