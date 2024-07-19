use std::collections::HashMap;
use std::hash::Hash;

use crate::core_::storage;

pub struct InMemStorage<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> InMemStorage<K, V> {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
}

impl<K, V> storage::Storage<K, V> for InMemStorage<K, V>
where
    K: Eq + PartialEq + Hash,
    V: 'static,
{
    async fn put(&mut self, k: K, v: V) -> Result<(), storage::Error> {
        self.map.insert(k, v);
        Ok(())
    }

    async fn get(&self, k: &K) -> Result<&V, storage::Error> {
        let v = self.map.get(k);
        Ok(v.unwrap())
    }

    async fn delete(&mut self, k: &K) -> Result<(), storage::Error> {
        let _ = self.map.remove(k);
        Ok(())
    }
}