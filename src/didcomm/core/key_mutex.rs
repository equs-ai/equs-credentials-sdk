use async_lock::{Mutex as AsyncMutex, Semaphore, SemaphoreGuardArc};
use std::{collections::HashMap, sync::Arc};

/// A map from keys to semaphores with 1 permit each
#[derive(Clone, Default)]
pub struct KeyMutex {
    inner: Arc<AsyncMutex<HashMap<String, Arc<Semaphore>>>>,
}

impl KeyMutex {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }

    /// Acquire the lock for `key`
    pub async fn lock(&self, key: impl Into<String>) -> SemaphoreGuardArc {
        let sem = {
            let mut map = self.inner.lock().await;
            map.entry(key.into())
                .or_insert_with(|| Arc::new(Semaphore::new(1)))
                .clone()
        };

        sem.acquire_arc().await
    }

    /// Try acquire the lock for `key`
    pub async fn try_lock(&self, key: impl Into<String>) -> Option<SemaphoreGuardArc> {
        let mut map = self.inner.lock().await;
        map.entry(key.into())
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .try_acquire_arc()
    }
}
