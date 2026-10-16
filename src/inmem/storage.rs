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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_returns_empty_storage() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        assert!(s.get_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn put_inserts_new_key_value_pair() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        s.put("k".to_string(), "v".to_string()).await.unwrap();

        assert_eq!(
            s.get(&"k".to_string()).await.unwrap(),
            Some("v".to_string())
        );
    }

    #[tokio::test]
    async fn put_overwrites_existing_value_at_same_key() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        s.put("k".to_string(), "v1".to_string()).await.unwrap();
        s.put("k".to_string(), "v2".to_string()).await.unwrap();

        assert_eq!(
            s.get(&"k".to_string()).await.unwrap(),
            Some("v2".to_string())
        );
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_key() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        assert_eq!(s.get(&"missing".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_all_returns_all_inserted_values() {
        let s: InMemStorage<String, u32> = InMemStorage::new();

        s.put("a".to_string(), 1).await.unwrap();
        s.put("b".to_string(), 2).await.unwrap();
        s.put("c".to_string(), 3).await.unwrap();

        let mut all = s.get_all().await.unwrap();
        all.sort();
        assert_eq!(all, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn delete_removes_existing_entry() {
        let s: InMemStorage<String, String> = InMemStorage::new();
        s.put("k".to_string(), "v".to_string()).await.unwrap();

        s.delete(&"k".to_string()).await.unwrap();

        assert_eq!(s.get(&"k".to_string()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_is_noop_for_missing_key() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        // Should not panic or error.
        s.delete(&"missing".to_string()).await.unwrap();
    }

    #[tokio::test]
    async fn transaction_put_inserts_into_underlying_storage() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        let mut txn = s.begin_transaction().await;
        txn.put("k".to_string(), "v".to_string()).unwrap();
        drop(txn);

        assert_eq!(
            s.get(&"k".to_string()).await.unwrap(),
            Some("v".to_string())
        );
    }

    #[tokio::test]
    async fn transaction_get_reflects_writes_made_in_the_same_transaction() {
        let s: InMemStorage<String, String> = InMemStorage::new();

        let mut txn = s.begin_transaction().await;
        txn.put("k".to_string(), "v".to_string()).unwrap();

        assert_eq!(txn.get(&"k".to_string()).unwrap(), Some("v".to_string()));
    }

    #[tokio::test]
    async fn transaction_delete_removes_entry_within_transaction() {
        let s: InMemStorage<String, String> = InMemStorage::new();
        s.put("k".to_string(), "v".to_string()).await.unwrap();

        let mut txn = s.begin_transaction().await;
        txn.delete(&"k".to_string()).unwrap();

        assert_eq!(txn.get(&"k".to_string()).unwrap(), None);
    }

    #[tokio::test]
    async fn transaction_get_all_returns_every_value() {
        let s: InMemStorage<String, u32> = InMemStorage::new();
        s.put("a".to_string(), 1).await.unwrap();
        s.put("b".to_string(), 2).await.unwrap();

        let txn = s.begin_transaction().await;
        let mut all = txn.get_all().unwrap();
        all.sort();

        assert_eq!(all, vec![1, 2]);
    }
}
