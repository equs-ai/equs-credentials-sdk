use async_rwlock::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{instrument, Level};

#[derive(Debug, Clone)]
pub struct TagStorage {
    tags: Arc<RwLock<HashMap<String, Vec<String>>>>,
    tag_names: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

pub type Tag = (String, String);

impl TagStorage {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            tags: Arc::new(RwLock::new(HashMap::new())),
            tag_names: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub async fn put_tag(&self, tag: &Tag, storage_id: &str) {
        let (k, v) = tag;
        let index = format!("{k}:{v}");

        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.tags.read().await.get(&index) {
            vec.extend(existing.to_owned());
        }

        self.tags.write().await.insert(index, vec);
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub async fn put_tag_name(&self, tag_name: String, storage_id: &str) {
        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.tag_names.read().await.get(&tag_name) {
            vec.extend(existing.to_owned());
        }

        self.tag_names.write().await.insert(tag_name, vec);
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub async fn get_ids(&self, tag: &Tag) -> HashSet<String> {
        let (k, v) = tag;
        let index = format!("{k}:{v}");

        let vec = self.tags.read().await.get(&index);

        let mut ids = HashSet::new();
        if let Some(existing) = self.tags.read().await.get(&index) {
            ids.extend(existing.to_owned())
        }

        ids
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub async fn get_ids_for_tag_names(&self, tag_names: Vec<String>) -> HashSet<String> {
        let map = self.tag_names.read().await;

        let mut ids = HashSet::new();

        for tag_name in tag_names.iter() {
            let tag_ids = map.get(tag_name).cloned().unwrap_or(Vec::new());
            ids.extend(tag_ids);
        }

        ids
    }
}
