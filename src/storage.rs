use async_trait::async_trait;

// Error handling
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    // TODO: change `get` to return Option<V> in result?
    #[error("Value for the key '{0}' is not found in storage.")]
    ValueNotFound(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Collision: {0}")]
    Collision(String),
}

#[async_trait]
pub trait Storage<K, V>: Send + Sync
where
    V: 'static + Send + Sync,
    K: Send + Sync,
{
    async fn put(&self, k: K, v: V) -> Result<(), Error>;

    async fn get(&self, k: &K) -> Result<V, Error>;

    async fn delete(&self, k: &K) -> Result<(), Error>;
}