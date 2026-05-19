//! APIs for implementing Nonce generator.

use crate::utils::b64;
use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use std::fmt::Debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A nonce value to assign a value into `Nonce`.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, ZeroizeOnDrop)]
pub struct Nonce(String);

impl Nonce {
    pub fn new<const N: usize>(data: [u8; N]) -> Self {
        let nonce = Self(b64::encode(&data));
        let mut data = data;
        data.zeroize();
        nonce
    }

    pub fn from_secret(secret: String) -> Self {
        Self(secret)
    }

    pub fn secret(&self) -> &str {
        &self.0
    }
}

/// `NonceGenerator` Error.
///
/// All implementations of [NonceHandler] should leverage this enum for error handling.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Nonce generation error: {details}"))]
    Generate {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Nonce validation error: {details}"))]
    Validate {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

/// `Result` alias for Nonce-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// An async generic `NonceHandler` interface for generating nonce.
///
/// Supports `generate` and `with_expiration` operations.
///
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NonceHandler: WasmNotSend + WasmNotSync {
    /// Generates a `Nonce`.
    ///
    ///
    /// # Returns
    ///
    /// `Nonce` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Generate] - fails to generate the `Nonce`.
    async fn generate(&self) -> Result<Nonce>;

    /// Validate the existence and expiration of a `Nonce`.
    ///
    /// # Arguments
    ///
    /// * `nonce` -`Nonce` to validate.
    ///
    /// # Returns
    ///
    /// `true` if nonce is active or valid.
    ///
    /// # Errors
    ///
    /// * [Error::Validate] - fails to validate a 'Nonce'.
    async fn validate(&self, nonce: &Nonce) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::Nonce;
    use crate::utils::b64;
    use zeroize::ZeroizeOnDrop;

    #[tokio::test]
    async fn nonce_implements_zeroize_on_drop() {
        let nonce = Nonce::from_secret("secret".to_owned());

        assert_zeroize_on_drop_is_implemented(nonce);
    }

    // This function is intended to verify (in compile time)
    // that the Nonce struct implements the ZeroizeOnDrop trait.
    // The idea behind this function is to prevent accidental removal
    // the ZeroizeOnDrop implementation that is important for security.
    fn assert_zeroize_on_drop_is_implemented(x: impl ZeroizeOnDrop) {}

    #[test]
    fn new_encodes_input_bytes_as_url_safe_base64() {
        let data: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let expected = b64::encode(&data);

        let nonce = Nonce::new(data);

        assert_eq!(nonce.secret(), expected.as_str());
        assert!(!nonce.secret().is_empty());
    }

    #[test]
    fn new_with_empty_array_produces_empty_secret() {
        let nonce = Nonce::new::<0>([]);

        assert_eq!(nonce.secret(), "");
    }

    #[test]
    fn from_secret_wraps_string_verbatim() {
        let nonce = Nonce::from_secret("raw-secret-123".to_string());

        assert_eq!(nonce.secret(), "raw-secret-123");
    }

    #[test]
    fn secret_returns_inner_string() {
        let nonce = Nonce::from_secret(String::new());

        assert_eq!(nonce.secret(), "");
    }
}
