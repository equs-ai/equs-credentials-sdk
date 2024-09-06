use crate::storage::Result;
use crate::storage::Storage;
use async_rwlock::RwLock;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;

pub struct InMemStorage<K, V> {
    map: RwLock<HashMap<K, V>>,
}

impl<K, V> InMemStorage<K, V> {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<K, V> Storage<K, V> for InMemStorage<K, V>
where
    K: Display + Eq + PartialEq + Hash + Sync + Send,
    V: 'static + Sync + Send + Clone,
{
    async fn put(&self, k: K, v: V) -> Result<()> {
        self.map.write().await.insert(k, v);
        Ok(())
    }

    async fn get(&self, k: &K) -> Result<Option<V>> {
        let v = self.map.read().await.get(k).cloned();
        Ok(v)
    }

    async fn delete(&self, k: &K) -> Result<()> {
        let _ = self.map.write().await.remove(k);
        Ok(())
    }
}
