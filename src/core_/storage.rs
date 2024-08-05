use async_trait::async_trait;

// Error handling
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("Value for the key '{0}' is not found in storage.")]
    ValueNotFound(String),
}

#[async_trait]
pub trait Storage<K, V>: Send + Sync
where
    V: 'static + Send + Sync,
    K: Send + Sync,
{
    async fn put(&mut self, k: K, v: V) -> Result<(), Error>;

    async fn get(&self, k: &K) -> Result<&V, Error>;

    async fn delete(&mut self, k: &K) -> Result<(), Error>;
}