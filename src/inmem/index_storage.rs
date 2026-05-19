use async_lock::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{Level, instrument};

type Level_ = Level;

#[derive(Debug, Clone)]
pub struct IndexStorage {
    indexes: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

pub type Tag = (String, String);

impl IndexStorage {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            indexes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub async fn put_index(&self, index: String, storage_id: &str) {
        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.indexes.read().await.get(&index) {
            vec.extend(existing.to_owned());
        }

        self.indexes.write().await.insert(index, vec);
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub async fn get_ids_for_indexes(&self, indexes: Vec<String>) -> HashSet<String> {
        let map = self.indexes.read().await;

        let mut ids = HashSet::new();

        for field in indexes.iter() {
            let field_ids = map.get(field).cloned().unwrap_or(Vec::new());
            ids.extend(field_ids);
        }

        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_returns_empty_index_storage() {
        let s = IndexStorage::new();

        assert!(
            s.get_ids_for_indexes(vec!["any".to_string()])
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn put_index_stores_first_storage_id_for_new_index() {
        let s = IndexStorage::new();

        s.put_index("field1".to_string(), "id1").await;

        assert_eq!(
            s.get_ids_for_indexes(vec!["field1".to_string()]).await,
            HashSet::from(["id1".to_string()])
        );
    }

    #[tokio::test]
    async fn put_index_appends_additional_storage_ids_for_same_index() {
        let s = IndexStorage::new();

        s.put_index("field1".to_string(), "id1").await;
        s.put_index("field1".to_string(), "id2").await;

        assert_eq!(
            s.get_ids_for_indexes(vec!["field1".to_string()]).await,
            HashSet::from(["id1".to_string(), "id2".to_string()])
        );
    }

    #[tokio::test]
    async fn get_ids_for_indexes_returns_empty_for_unknown_index() {
        let s = IndexStorage::new();
        s.put_index("field1".to_string(), "id1").await;

        assert!(
            s.get_ids_for_indexes(vec!["missing".to_string()])
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn get_ids_for_indexes_returns_union_across_multiple_indexes() {
        let s = IndexStorage::new();
        s.put_index("field1".to_string(), "id1").await;
        s.put_index("field2".to_string(), "id2").await;
        // id1 appears in two indexes — the union deduplicates it.
        s.put_index("field3".to_string(), "id1").await;

        let ids = s
            .get_ids_for_indexes(vec![
                "field1".to_string(),
                "field2".to_string(),
                "field3".to_string(),
            ])
            .await;

        assert_eq!(ids, HashSet::from(["id1".to_string(), "id2".to_string()]));
    }

    #[tokio::test]
    async fn get_ids_for_indexes_with_empty_query_returns_empty() {
        let s = IndexStorage::new();
        s.put_index("field1".to_string(), "id1").await;

        assert!(s.get_ids_for_indexes(vec![]).await.is_empty());
    }
}
