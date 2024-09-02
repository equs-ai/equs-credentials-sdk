use std::fmt::Debug;
use async_trait::async_trait;
use snafu::{Location, Snafu};

/// `Storage` Error.
///
/// All implementations of [Storage] should leverage this enum for error handling.
#[derive(Snafu)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Value resolving error at {location}\n Cause: {details}"))]
    Resolving {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Storage modification error at {location}\n Cause: {details}"))]
    Modification {
        details: String,
        #[snafu(implicit)]
        location: Location,
    }
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;
        Ok(())
    }
}

/// `Result` alias for Storage-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// An async generic key-value `Storage` interface for managing arbitrary data.
///
/// Supports basic `put`, `get` and `delete` operations.
#[async_trait]
pub trait Storage<K, V>: Send + Sync
where
    V: 'static + Send + Sync,
    K: Send + Sync,
{
    /// Put a key-value into the storage.
    ///
    /// # Arguments
    ///
    /// * `k` - the key.
    /// * `v` - the value.
    ///
    /// # Errors
    ///
    /// * [Error::Collision] - collision on inserting the key-value.
    /// * [Error::Network] - fails to make a network call.
    async fn put(&self, k: K, v: V) -> Result<()>;

    /// Returns a value for the provided key.
    ///
    /// # Arguments
    ///
    /// * `k` - a key.
    ///
    /// # Returns
    ///
    /// `Some(value)` on success.
    /// `None` if no value was found by `key`.
    ///
    /// # Errors
    ///
    /// * [Error::Network] - fails to make a network call.
    async fn get(&self, k: &K) -> Result<Option<V>>;

    /// Delete an entry from the `Storage`.
    ///
    /// # Arguments
    ///
    /// * `k` - a key.
    ///
    /// # Errors
    ///
    /// * [Error::Network] - fails to make a network call.
    async fn delete(&self, k: &K) -> Result<()>;
}