//! APIs for implementing Nonce generator.

use crate::utils::b64;
use crate::utils::serde::{int_to_duration, int_to_offset_date_time};
use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use std::fmt::Debug;
use std::ops::Add;
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A struct containing nonce with created time and duration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NonceData {
    pub value: Nonce,
    #[serde(deserialize_with = "int_to_offset_date_time")]
    pub created: OffsetDateTime,
    #[serde(deserialize_with = "int_to_duration")]
    pub expires_in: Option<Duration>,
}

impl NonceData {
    pub(crate) fn secret(&self) -> &str {
        self.value.secret()
    }
}

impl NonceData {
    pub fn is_expired(&self) -> bool {
        if let Some(expires_in) = self.expires_in {
            let expires = self.created.add(expires_in);
            return OffsetDateTime::now_utc() > expires;
        }

        false
    }
}

/// A nonce value to assign a value into `Nonce`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ZeroizeOnDrop)]
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
/// All implementations of [NonceGenerator] should leverage this enum for error handling.
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
}

/// `Result` alias for Nonce-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// An async generic `NonceGenerator` interface for generating nonce.
///
/// Supports `generate` and `with_expiration` operations.
#[async_trait]
pub trait NonceGenerator: Send + Sync {
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

    /// Creates a `NonceData` with a provided expiration.
    ///
    /// # Arguments
    ///
    /// * `expiration` - an active duration of `Nonce`.
    ///
    /// # Returns
    ///
    /// A `NonceData` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Generate] - fails to generate the `NonceData`.
    async fn with_expiration(&self, expiration: Duration) -> Result<NonceData> {
        let nonce = self.generate().await?;

        let nonce_data = NonceData {
            value: nonce,
            created: OffsetDateTime::now_utc(),
            expires_in: Some(expiration),
        };

        Ok(nonce_data)
    }
}

#[cfg(test)]
mod tests {
    use super::Nonce;
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
}
