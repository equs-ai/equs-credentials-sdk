//! APIs for implementing Key Management Service.

use crate::crypto;
use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use async_trait::async_trait;
use common_macros::DebugError;
#[cfg(test)]
use mockall::automock;
use snafu::{Location, Snafu};
use std::fmt::Debug;
use strum_macros::{Display, EnumIter, EnumString, IntoStaticStr};
use tracing::{Level, info, instrument};
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
    #[snafu(display("Key get error: {details}"))]
    Get { details: String },
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
    #[snafu(display("Key derivation error: {details}"))]
    Derivation {
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
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Kms<KH>: WasmNotSend + WasmNotSync
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

/// Capability trait for raw-bytes JWE decryption.
///
/// Implemented automatically for any [`Kms`] whose [`KeyHandle`] implements
/// [`KeyAgreement`] (see [`crate::jwe`]).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait JweDecryptBytes<KH: KeyHandle> {
    async fn decrypt_bytes(
        &self,
        jwe: &str,
    ) -> core::result::Result<Vec<u8>, crate::jwe::JweDecryptError>;
}

/// Diffie-Hellman key-agreement capability for a [`KeyHandle`].
///
/// A handle that can perform ECDH derives the **raw shared secret** internally,
/// without exposing its private key material. This is the capability JWE
/// decryption is built on (see [`crate::jwe`]): the KMS performs the exchange
/// against the stored key, mirroring a remote KMS's `DeriveSharedSecret`
/// operation (e.g. AWS KMS), which never exports the key.
///
/// Implementing it opts a [`Kms`] into the blanket [`crate::jwe::JweDecrypt`]
/// and [`JweDecryptBytes`] impls.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait KeyAgreement {
    /// Perform an ECDH key exchange between this key and the remote public key,
    /// returning the raw shared-secret bytes.
    ///
    /// # Arguments
    ///
    /// * `remote_jwk` - the remote (ephemeral) public key as a JWK JSON string.
    ///
    /// # Errors
    ///
    /// * [crypto::Error] - the key type does not support agreement, or the
    ///   remote key could not be parsed.
    async fn shared_secret(&self, remote_jwk: &str) -> crypto::Result<Vec<u8>>;
}

/// An async `DerivativeKms` is an extension for `Kms` to support key derivation.
///
/// Could be implemented by any adapter to be used with `ASDK`.
///
/// Adds up master key's creation from a seed and derivation.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
mod tests {
    use crate::inmem::kms::LocalKms;
    use crate::kms::{CreateOptions, KeyType, Kms};

    #[tokio::test]
    async fn create_and_handle_returns_consistent_kid_and_handle() {
        let kms = LocalKms::new();

        let (kid, handle) = kms
            .create_and_handle(KeyType::Ed25519, CreateOptions::default())
            .await
            .unwrap();

        assert!(!kid.is_empty());

        // The handle returned should round-trip back to the same key id
        // when looked up via the public key.
        let pub_key = crate::crypto::Key::pub_key(&handle).unwrap();
        let resolved = kms.get_by_public_key(&pub_key).await.unwrap();
        assert_eq!(
            crate::crypto::Key::pub_key(&resolved).unwrap(),
            pub_key,
            "handle returned by create_and_handle must reference the same key"
        );
    }

    // Exercises the default body of `Kms::create_and_handle`: when `create`
    // succeeds but `get` fails, the error from `get` must propagate untouched.
    // Mockall auto-mocks `create_and_handle` itself, so we can't use `MockKms`
    // here — we need a real impl whose default body actually runs.
    #[tokio::test]
    #[should_panic(expected = "Key not found for ID: kid-fixture")]
    async fn create_and_handle_propagates_get_error_after_successful_create() {
        use crate::kms::Error;
        use crate::utils::test_utils::MockKey;
        use async_trait::async_trait;

        struct FailingGetKms;

        #[async_trait]
        impl Kms<MockKey> for FailingGetKms {
            async fn create(
                &self,
                _kt: KeyType,
                _opts: CreateOptions,
            ) -> crate::kms::Result<crate::kms::KeyID> {
                Ok("kid-fixture".to_string())
            }

            async fn get(&self, _kid: &crate::kms::KeyID) -> crate::kms::Result<MockKey> {
                Err(Error::NotFound {
                    id: "kid-fixture".to_string(),
                })
            }

            async fn get_by_public_key(&self, _public_key: &[u8]) -> crate::kms::Result<MockKey> {
                unimplemented!()
            }
        }

        let kms = FailingGetKms;

        // The default body of `create_and_handle` calls `create` (Ok) then
        // `get` (Err); the `?` operator propagates the error and the `.unwrap()`
        // below panics with the error's Display message.
        kms.create_and_handle(KeyType::Ed25519, CreateOptions::default())
            .await
            .unwrap();
    }
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
