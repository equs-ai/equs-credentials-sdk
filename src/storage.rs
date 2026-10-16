//! APIs for implementing Storage.

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
    V: Send + Sync + 'static,
    K: Send + Sync,
{
    /// Scoped handle returned by [Storage::begin_transaction].
    type Transaction: Transaction<K, V> + Send + Sync + 'static;

    /// Starts a storage transaction.
    ///
    /// # Returns
    /// A [Storage::Transaction]; it ends when dropped, with no explicit commit.
    async fn begin_transaction(&self) -> Self::Transaction;

    /// Puts a key-value into the storage.
    ///
    /// # Arguments
    /// * `k` - the key
    /// * `v` - the value
    ///
    /// # Errors
    /// * [Error::Modification] - the key-value could not be inserted
    async fn put(&self, k: K, v: V) -> Result<()>;

    /// Returns the value for the provided key.
    ///
    /// # Arguments
    /// * `k` - the key
    ///
    /// # Returns
    /// `Some(value)`, or `None` if the key is absent.
    ///
    /// # Errors
    /// * [Error::Resolving] - the value could not be resolved
    async fn get(&self, k: &K) -> Result<Option<V>>;

    /// Returns all values.
    ///
    /// # Returns
    /// Every stored value; empty if there are none.
    ///
    /// # Errors
    /// * [Error::Resolving] - the values could not be resolved
    async fn get_all(&self) -> Result<Vec<V>>;

    /// Deletes an entry from the `Storage`.
    ///
    /// # Arguments
    /// * `k` - the key
    ///
    /// # Errors
    /// * [Error::Modification] - the record could not be deleted
    async fn delete(&self, k: &K) -> Result<()>;
}

/// Synchronous view of a [Storage] opened by [Storage::begin_transaction]; reads observe its own
/// writes, and dropping it ends the transaction without rollback.
pub trait Transaction<K, V>
where
    V: Send + Sync + 'static,
    K: Send + Sync,
{
    /// Puts a key-value into the storage.
    ///
    /// # Arguments
    /// * `key` - the key
    /// * `value` - the value
    ///
    /// # Errors
    /// * [Error::Modification] - the key-value could not be inserted
    fn put(&mut self, key: K, value: V) -> Result<()>;

    /// Returns the value for the provided key.
    ///
    /// # Arguments
    /// * `k` - the key
    ///
    /// # Returns
    /// `Some(value)`, or `None` if the key is absent.
    ///
    /// # Errors
    /// * [Error::Resolving] - the value could not be resolved
    fn get(&self, k: &K) -> Result<Option<V>>;

    /// Returns all values.
    ///
    /// # Returns
    /// Every stored value; empty if there are none.
    ///
    /// # Errors
    /// * [Error::Resolving] - the values could not be resolved
    fn get_all(&self) -> Result<Vec<V>>;

    /// Deletes an entry from the `Storage`.
    ///
    /// # Arguments
    /// * `k` - the key
    ///
    /// # Errors
    /// * [Error::Modification] - the record could not be deleted
    fn delete(&mut self, k: &K) -> Result<()>;
}
