use crate::utils::b64;
use crate::utils::serde::{int_to_duration, int_to_offset_date_time};
use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use std::fmt::Debug;
use std::ops::Add;
use time::{Duration, OffsetDateTime};

/// A struct containing nonce with created time and duration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Nonce(pub(crate) String);

impl Nonce {
    pub fn new(data: &[u8]) -> Self {
        Nonce(b64::encode(data))
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
    #[snafu(display("Nonce generation error at {location}\n Cause: {details}"))]
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
