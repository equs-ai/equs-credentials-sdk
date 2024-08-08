use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;

use async_trait::async_trait;

use crate::core_::storage;

#[derive(Clone)]
pub struct InMemStorage<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> InMemStorage<K, V> {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
}

#[async_trait]
impl<K, V> storage::Storage<K, V> for InMemStorage<K, V>
where
    K: Display + Eq + PartialEq + Hash + Sync + Send,
    V: 'static + Sync + Send,
{
    async fn put(&mut self, k: K, v: V) -> Result<(), storage::Error> {
        self.map.insert(k, v);
        Ok(())
    }

    async fn get(&self, k: &K) -> Result<&V, storage::Error> {
        let v = self.map.get(k);
        v.ok_or_else(|| storage::Error::ValueNotFound(k.to_string()))
    }

    async fn delete(&mut self, k: &K) -> Result<(), storage::Error> {
        let _ = self.map.remove(k);
        Ok(())
    }
}