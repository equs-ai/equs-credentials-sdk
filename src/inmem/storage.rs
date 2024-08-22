use async_rwlock::RwLock;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;

use crate::storage;

pub struct InMemStorage<K, V> {
    map: RwLock<HashMap<K, V>>,
}

impl<K, V> InMemStorage<K, V> {
    pub fn new() -> Self {
        Self { map: RwLock::new(HashMap::new()) }
    }
}

#[async_trait]
impl<K, V> storage::Storage<K, V> for InMemStorage<K, V>
where
    K: Display + Eq + PartialEq + Hash + Sync + Send,
    V: 'static + Sync + Send + Clone,
{
    async fn put(&self, k: K, v: V) -> Result<(), storage::Error> {
        self.map.write().await.insert(k, v);
        Ok(())
    }

    async fn get(&self, k: &K) -> Result<V, storage::Error> {
        let v = self.map.read().await.get(k).cloned();
        v.ok_or_else(|| storage::Error::ValueNotFound(k.to_string()))
    }

    async fn delete(&self, k: &K) -> Result<(), storage::Error> {
        let _ = self.map.write().await.remove(k);
        Ok(())
    }
}