use crate::crypto;
use async_trait::async_trait;
use snafu::{Location, Snafu};
use std::fmt::Debug;
use strum_macros::{Display, EnumString, IntoStaticStr};
use tracing::{instrument, trace, Level};

/// `Kms` Error.
///
/// All implementations of [Kms] should leverage this enum for error handling.
#[derive(Snafu)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Key not found for ID: {id}"))]
    NotFound { id: String },
    #[snafu(display("Key creation error at {location}\n Cause: {details}"))]
    Creation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Resolution error at {location}\n Cause: {details}"))]
    Resolving {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Crypto error at {location}\n Cause: {source}"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;
        Ok(())
    }
}

/// `Result` alias for Kms-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// Alias for `Kms` key id's.
pub type KeyID = String;

/// Enum with supported `Kms` key types.
///
/// *NOTE*: more key types to be supported later.
#[derive(Debug, PartialEq, Clone, Display, EnumString, IntoStaticStr)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    P256,
    // etc
}

pub const SUPPORTED_KEYS: [KeyType; 2] = [KeyType::Ed25519, KeyType::P256];

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
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
    )]
    async fn create_and_handle(&self, kt: KeyType, opts: CreateOptions) -> Result<(KeyID, KH)> {
        let kid = self.create(kt, opts).await?;
        let res = self.get(&kid).await?;

        trace!(created_key_id = ?kid);

        Ok((kid, res))
    }
}

#[cfg(test)]
pub mod test_util {
    use crate::kms;
    use crate::kms::{KeyHandle, Kms};

    pub async fn test_kms<KH: KeyHandle, KMS: Kms<KH>>(kms: KMS) {
        for kt in [kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Create a key
            let create_res = kms.create(kt.clone(), kms::CreateOptions {}).await;
            assert!(create_res.is_ok());
            let kid = create_res.unwrap();

            // Get a handle to the key
            let get_res = kms.get(&kid).await;
            assert!(get_res.is_ok());
            let kh = get_res.unwrap();

            // Sign using handle
            let message = "abracadabra";

            let s_res = kh.sign(message.as_bytes()).await;
            assert!(s_res.is_ok());

            let signature = s_res.unwrap();

            // Verify using handle
            let v_res = kh.verify(message.as_bytes(), &signature).await;
            assert!(v_res.is_ok());

            // Check JWK
            assert_ne!(kh.jwk(), None);

            // Print jwks
            let jwk = kh.jwk().unwrap();
            println!("JWK: {}", serde_json::to_string_pretty(&jwk).unwrap())
        }
    }
}
