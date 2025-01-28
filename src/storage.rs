use async_trait::async_trait;
use common_macros::DebugError;
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// `Storage` Error.
///
/// All implementations of [Storage] should leverage this enum for error handling.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Value resolving error: {details}"))]
    Resolving {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Storage modification error: {details}"))]
    Modification {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
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
    /// * [Error::Modification] - fails to insert the key-value.
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
    /// * [Error::Resolving] - fails to resolve a value.
    async fn get(&self, k: &K) -> Result<Option<V>>;

    /// Returns all values.
    ///
    /// # Returns
    ///
    /// `Vec<V>` on success.
    /// Empty vector if no keys were found.
    ///
    /// # Errors
    ///
    /// * [Error::Resolving] - fails to resolve a value.
    async fn get_all(&self) -> Result<Vec<V>>;

    /// Delete an entry from the `Storage`.
    ///
    /// # Arguments
    ///
    /// * `k` - a key.
    ///
    /// # Errors
    ///
    /// * [Error::Modification] - fails to delete the record.
    async fn delete(&self, k: &K) -> Result<()>;
}
