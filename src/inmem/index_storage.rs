use async_rwlock::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{instrument, Level};

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
