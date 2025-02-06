//! APIs for implementing Key Management Service.

use crate::crypto;
use async_trait::async_trait;
use common_macros::DebugError;
#[cfg(test)]
use mockall::automock;
use snafu::{Location, Snafu};
use std::fmt::Debug;
use strum_macros::{Display, EnumIter, EnumString, IntoStaticStr};
use tracing::{info, instrument, Level};
use zeroize::Zeroize;

/// `Kms` Error.
///
/// All implementations of [Kms] should leverage this enum for error handling.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Key not found for ID: {id}"))]
    NotFound { id: String },
    #[snafu(display("Key creation error: {details}"))]
    Creation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Resolution error: {details}"))]
    Resolving {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Crypto error"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
}

/// `Result` alias for Kms-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// Alias for `Kms` key id's.
pub type KeyID = String;

/// Enum with supported `Kms` key types.
///
/// *NOTE*: more key types to be supported later.
#[derive(Debug, PartialEq, Clone, Display, EnumIter, EnumString, IntoStaticStr)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    P256,
    K256,
    Bls12381,
    // etc
}

/// General options for key creation.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct CreateOptions {}

/// General-purpose `KeyHandle` trait.
///
/// `KeyHandle` allows basic crypto operations like signing, verifying and exposing the public key.
///
/// In general `KeyHandle` should not expose private key material.
///
/// # Errors
///
/// Refer to [crypto::Error] for more information.
pub trait KeyHandle: crypto::SigningKey + crypto::VerifyingKey + crypto::Key + Clone {}

/// An async `Kms` interface for handling the keys and basic crypto operations.
///
/// Should be implemented by any adapter to be used with `ASDK`.
///
/// Supports key's creation and retrieving the `KeyHandle` with support of basic `Crypto`.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Kms<KH>: Send + Sync
where
    KH: KeyHandle,
{
    /// Create and store a key in `Kms`.
    ///
    /// # Arguments
    ///
    /// * `kt` - a `KeyType` for the key.
    /// * `opts` - extra options for a key creation.
    ///
    /// # Returns
    ///
    /// A `KeyId` for the created key on success.
    ///
    /// # Errors
    ///
    /// * [Error::Creation] - fails to create a key.
    /// * [Error::Crypto] - crypto error, refer to [crypto::Error].
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> Result<KeyID>;

    /// Returns [KeyHandle] for the provided `KID`.
    ///
    /// # Arguments
    ///
    /// * `kid` - a `KeyId` of the requested key.
    ///
    /// # Returns
    ///
    /// A `KeyHandle` supporting basic crypto primitives on success.
    ///
    /// # Errors
    ///
    /// * [Error::NotFound] - key is not found.
    /// * [Error::Resolving] - fails to resolve a key.
    /// * [Error::Crypto] - crypto error, refer to [crypto::Error].
    async fn get(&self, kid: &KeyID) -> Result<KH>;

    /// Returns [KeyHandle] for the provided `Public Key`.
    ///
    /// # Arguments
    ///
    /// * `public_key` -  a `Public Key` of the requested key.
    ///
    /// # Returns
    ///
    /// A `KeyHandle` supporting basic crypto primitives on success.
    ///
    /// # Errors
    /// * [Error::NotFound] - key is not found.
    /// * [Error::Resolving] - fails to resolve a key.
    /// * [Error::Crypto] - crypto error, refer to [crypto::Error].
    async fn get_by_public_key(&self, public_key: &[u8]) -> Result<KH>;

    /// Utility method to create a key and get the corresponding [KeyHandle].
    ///
    /// # Arguments
    ///
    /// * `kt` - a `KeyType` for the key.
    /// * `opts` - extra options for a key creation.
    ///
    /// # Returns
    ///
    /// A tuple with `KeyId` and `KeyHandle` on success.
    ///
    /// # Errors
    ///
    /// See [Kms::create] and [Kms::get] errors.
    #[instrument(level = Level::TRACE, skip(self), err())]
    async fn create_and_handle(&self, kt: KeyType, opts: CreateOptions) -> Result<(KeyID, KH)> {
        let kid = self.create(kt, opts).await?;
        info!("created a key {kid}");
        let res = self.get(&kid).await?;

        Ok((kid, res))
    }
}

/// Enum with supported `Kms` derivation types.
///
/// *NOTE*: more key types to be supported later.
#[derive(Debug, PartialEq, Clone, Display, EnumString, IntoStaticStr)]
#[non_exhaustive]
pub enum DerivationType {
    BIP32,
    ECDH1PU,
    ECDHES,
    // etc
}

#[derive(Debug, PartialEq, Clone, Display)]
pub enum BIP32Params {
    MasterDerive { seed: Vec<u8> },
    ChildDerive { path: String, master_kid: KeyID },
}

/// Public and Private key pair.
#[derive(Debug, PartialEq, Clone)]
pub struct KeyPair {
    pub private_key: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
    }
}

/// Parameters required for performing an ECDH-1PU key derivation.
#[derive(Debug, PartialEq, Clone)]
pub struct ECDH1PUParams {
    pub key_type: KeyType,
    pub ephem_key: KeyPair,
    pub send_key: KeyPair,
    pub recip_key: KeyPair,
    pub alg: Vec<u8>,
    pub apu: Vec<u8>,
    pub apv: Vec<u8>,
    pub cc_tag: Vec<u8>,
    pub receive: bool,
}

/// Parameters required for performing an ECDH-ES key derivation.
#[derive(Debug, PartialEq, Clone)]
pub struct ECDHESParams {
    pub key_type: KeyType,
    pub ephem_key: KeyPair,
    pub recip_key: KeyPair,
    pub alg: Vec<u8>,
    pub apu: Vec<u8>,
    pub apv: Vec<u8>,
    pub receive: bool,
}

/// An async `DerivativeKms` is an extension for `Kms` to support key derivation.
///
/// Could be implemented by any adapter to be used with `ASDK`.
///
/// Adds up master key's creation from a seed and derivation.
#[async_trait]
pub trait DerivativeKms<DP>: Send + Sync {
    type Output;

    /// Derive a key using provided derivation method
    ///
    /// # Arguments
    ///
    /// * `derivation` - a derivation method.
    ///
    /// # Returns
    ///
    /// A `KeyId` for the derived key on success.
    ///
    /// # Errors
    ///
    /// * [Error::Creation] - fails to create a key.
    /// * [Error::Crypto] - crypto error, refer to [crypto::Error].
    async fn derive(&self, derivation: DP) -> Result<Self::Output>;
}

#[cfg(test)]
pub mod test_util {
    use crate::kms;
    use crate::kms::{KeyHandle, KeyType, Kms};
    use strum::IntoEnumIterator;

    pub async fn test_kms<KH: KeyHandle, KMS: Kms<KH>>(kms: KMS) {
        for kt in KeyType::iter() {
            // Create a key
            let kid = kms
                .create(kt.clone(), kms::CreateOptions::default())
                .await
                .unwrap();

            // Get a handle to the key
            let kh = kms.get(&kid).await.unwrap();

            // Get a handle to the key by public key
            kms.get_by_public_key(&kh.pub_key().unwrap()).await.unwrap();

            // Sign using handle
            let message = "abracadabra";
            let signature = kh.sign(message.as_bytes()).await.unwrap();

            // Verify using handle
            kh.verify(message.as_bytes(), &signature).await.unwrap();

            // Check JWK
            assert_ne!(kh.jwk(), None);

            // Print jwks
            let jwk = kh.jwk().unwrap();
            println!("JWK: {}", serde_json::to_string_pretty(&jwk).unwrap())
        }
    }
}
