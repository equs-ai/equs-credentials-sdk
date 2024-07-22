use std::fmt;

// Error handling
#[derive(fmt::Debug)]
pub enum Error {}

pub trait Storage<K, V>
where
    V: 'static,
{
    async fn put(&mut self, k: K, v: V) -> Result<(), Error>;

    async fn get(&self, k: &K) -> Result<&V, Error>;

    async fn delete(&mut self, k: &K) -> Result<(), Error>;
}