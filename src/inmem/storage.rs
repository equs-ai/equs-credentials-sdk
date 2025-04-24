use crate::storage::Storage;
use crate::storage::{Result, Transaction};
use async_lock::{RwLock, RwLockWriteGuardArc};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct InMemStorage<K, V> {
    map: Arc<RwLock<HashMap<K, V>>>,
}

impl<K, V> InMemStorage<K, V> {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl<K, V> Storage<K, V> for InMemStorage<K, V>
where
    K: Display + Eq + PartialEq + Hash + Send + Sync + 'static,
    V: Sync + Send + Clone + 'static,
{
    type Transaction = InMemStorageTransaction<K, V>;

    async fn begin_transaction(&self) -> InMemStorageTransaction<K, V> {
        let guard = self.map.write_arc().await;

        InMemStorageTransaction { guard }
    }

    async fn put(&self, k: K, v: V) -> Result<()> {
        self.map.write().await.insert(k, v);
        Ok(())
    }

    async fn get(&self, k: &K) -> Result<Option<V>> {
        let v = self.map.read().await.get(k).cloned();
        Ok(v)
    }

    async fn get_all(&self) -> Result<Vec<V>> {
        let v = self.map.read().await.values().cloned().collect();
        Ok(v)
    }

    async fn delete(&self, k: &K) -> Result<()> {
        let _ = self.map.write().await.remove(k);
        Ok(())
    }
}

pub struct InMemStorageTransaction<K, V> {
    guard: RwLockWriteGuardArc<HashMap<K, V>>,
}

impl<K, V> Transaction<K, V> for InMemStorageTransaction<K, V>
where
    K: Display + Eq + PartialEq + Hash + Send + Sync + 'static,
    V: Sync + Send + Clone + 'static,
{
    fn put(&mut self, key: K, value: V) -> Result<()> {
        self.guard.insert(key, value);

        Ok(())
    }

    fn get(&self, key: &K) -> Result<Option<V>> {
        let v = self.guard.get(key).cloned();

        Ok(v)
    }

    fn get_all(&self) -> Result<Vec<V>> {
        Ok(self.guard.values().cloned().collect())
    }

    fn delete(&mut self, key: &K) -> Result<()> {
        self.guard.remove(key);

        Ok(())
    }
}
