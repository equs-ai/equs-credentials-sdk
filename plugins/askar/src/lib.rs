use aries_askar::entry::{Entry, TagFilter};
use aries_askar::storage::KdfMethod;
use aries_askar::storage::backend::OrderBy;
use aries_askar::{Error, ErrorKind, PassKey, Session, Store, StoreKeyMethod};
use serde::Deserialize;
use tracing::{Level, instrument};
use zeroize::Zeroize;

pub mod kms;
pub mod vault;

#[derive(Clone, Debug)]
pub struct AskarStorage {
    store: Store,
    profile: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AskarStorageConfig {
    pub db_url: String,
    pub key_method: KeyMethod,
    pub pass_key: String,
    pub profile: String,
}

impl Drop for AskarStorageConfig {
    fn drop(&mut self) {
        self.profile.zeroize();
        self.pass_key.zeroize();
    }
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum KeyMethod {
    DeriveKey,
    RawKey,
    Unprotected,
}

pub type AskarStorageScan<'a> = aries_askar::entry::Scan<'a, Entry>;

#[derive(Debug)]
pub struct AskarStorageScanParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub tag_filter: Option<TagFilter>,
    pub order_by: Option<OrderBy>,
    pub sort_by_desc: Option<bool>,
    pub profile: Option<String>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl AskarStorage {
    /// Provision a new store instance using a config
    #[instrument(level = Level::TRACE err(), ret())]
    pub async fn create(config: &AskarStorageConfig, recreate: bool) -> Result<AskarStorage> {
        let pass_key = PassKey::from(config.pass_key.clone());
        let profile = config.profile.to_owned();

        let store = Store::provision(
            &config.db_url,
            (&config.key_method).into(),
            pass_key,
            Some(profile.clone()),
            recreate,
        )
        .await?;

        Ok(AskarStorage { store, profile })
    }

    /// Open a store instance by using a config
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn open(config: &AskarStorageConfig) -> Result<AskarStorage> {
        let pass_key = PassKey::from(config.pass_key.as_str());
        let profile = config.profile.to_owned();

        let store = Store::open(
            &config.db_url,
            Some((&config.key_method).into()),
            pass_key,
            Some(config.profile.to_owned()),
        )
        .await?;

        Ok(AskarStorage { store, profile })
    }

    /// Create a new scan instance against the store
    ///
    /// The result will keep an open connection to the backend until it is consumed
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn scan<'a>(&self, params: AskarStorageScanParams) -> Result<AskarStorageScan<'a>> {
        self.store
            .scan(
                Some(params.profile.unwrap_or(self.profile.clone())),
                None,
                params.tag_filter,
                params.offset,
                params.limit,
                params.order_by,
                params.sort_by_desc.unwrap_or_default(),
            )
            .await
    }

    /// Remove a store instance using a database URL
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn remove(db_url: &str) -> Result<bool> {
        Store::remove(db_url).await
    }

    /// Close the store instance, waiting for any shutdown procedures to complete.
    #[instrument(
        level = Level::TRACE, skip_all, err(), ret())]
    pub async fn close(self) -> Result<()> {
        self.store.close().await
    }

    /// Ensure a profile with the given name exists, creating it if it does not
    ///
    /// Idempotent: an already-present profile is reported as success, so callers
    /// re-provisioning a known profile do not have to invent a fresh name.
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn ensure_profile(&self, profile: String) -> Result<String> {
        match self.store.create_profile(Some(profile.clone())).await {
            Ok(name) => Ok(name),
            Err(e) if e.kind() == ErrorKind::Duplicate => Ok(profile),
            Err(e) => Err(e),
        }
    }

    /// Create an active profile to store instance
    #[instrument(level = Level::TRACE, ret())]
    pub fn get_active_profile(&self) -> String {
        self.profile.clone()
    }

    /// Change an active profile against store instance
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn change_active_profile(&mut self, profile: String) -> Result<()> {
        let _ = self.store.session(Some(profile.clone())).await?;
        self.profile = profile;

        Ok(())
    }

    /// Remove an existing profile with the given profile name
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn remove_profile(&self, profile: String) -> Result<bool> {
        self.store.remove_profile(profile).await
    }

    /// Create a new session against the store
    #[instrument(level = Level::TRACE, err(), ret())]
    pub(crate) async fn session(&self, profile: Option<String>) -> Result<Session> {
        self.store
            .session(Some(profile.unwrap_or(self.profile.clone())))
            .await
    }

    /// Create a new transaction session against the store
    #[allow(dead_code)] // todo fix
    #[instrument(level = Level::TRACE, err(), ret())]
    pub(crate) async fn transaction(&self, profile: Option<String>) -> Result<Session> {
        self.store
            .transaction(Some(profile.unwrap_or(self.profile.clone())))
            .await
    }
}

impl From<&KeyMethod> for StoreKeyMethod {
    fn from(value: &KeyMethod) -> Self {
        match value {
            KeyMethod::DeriveKey => {
                StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()))
            }
            KeyMethod::RawKey => StoreKeyMethod::RawKey,
            KeyMethod::Unprotected => StoreKeyMethod::Unprotected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AskarStorage, AskarStorageConfig, KeyMethod};

    #[tokio::test]
    async fn ensure_profile_creates_a_missing_profile() {
        let storage = create_test_storage().await;

        let created = storage
            .ensure_profile("wallet_a".to_string())
            .await
            .unwrap();

        assert_eq!(created, "wallet_a");
        assert_eq!(profile_count(&storage, "wallet_a").await, 1);
    }

    #[tokio::test]
    async fn ensure_profile_is_idempotent_for_an_existing_profile() {
        let storage = create_test_storage().await;

        let first = storage
            .ensure_profile("wallet_a".to_string())
            .await
            .unwrap();
        let second = storage
            .ensure_profile("wallet_a".to_string())
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(profile_count(&storage, "wallet_a").await, 1);
    }

    /// Callers used to work around the `Duplicate` error by provisioning a
    /// uniquely named profile per attempt, and every distinct name pins a
    /// profile key in the backend key cache for the lifetime of the store.
    /// Re-provisioning must stay a no-op so no caller needs that workaround.
    #[tokio::test]
    async fn repeated_ensure_profile_does_not_grow_the_profile_set() {
        let storage = create_test_storage().await;
        let before = all_profiles(&storage).await.len();

        for _ in 0..10 {
            storage
                .ensure_profile("wallet_a".to_string())
                .await
                .unwrap();
        }

        assert_eq!(all_profiles(&storage).await.len(), before + 1);
    }

    #[tokio::test]
    async fn ensure_profile_keeps_the_data_of_an_existing_profile_readable() {
        let storage = create_test_storage().await;
        storage
            .ensure_profile("wallet_a".to_string())
            .await
            .unwrap();

        let mut session = storage.session(Some("wallet_a".to_string())).await.unwrap();
        session
            .insert("item", "entry_a", b"payload", None, None)
            .await
            .unwrap();
        session.commit().await.unwrap();

        storage
            .ensure_profile("wallet_a".to_string())
            .await
            .unwrap();

        let mut session = storage.session(Some("wallet_a".to_string())).await.unwrap();
        let entry = session.fetch("item", "entry_a", false).await.unwrap();
        assert_eq!(entry.unwrap().value.as_ref(), b"payload");
    }

    #[tokio::test]
    async fn ensure_profile_propagates_errors_other_than_duplicate() {
        let storage = create_test_storage().await;
        storage.clone().close().await.unwrap();

        let err = storage
            .ensure_profile("wallet_a".to_string())
            .await
            .expect_err("a closed store must not silently report success");

        assert_ne!(err.kind(), super::ErrorKind::Duplicate);
    }

    async fn create_test_storage() -> AskarStorage {
        AskarStorage::create(
            &AskarStorageConfig {
                db_url: "sqlite://:memory:".to_owned(),
                key_method: KeyMethod::DeriveKey,
                pass_key: "1234".to_string(),
                profile: "test".to_string(),
            },
            false,
        )
        .await
        .unwrap()
    }

    async fn all_profiles(storage: &AskarStorage) -> Vec<String> {
        storage.store.list_profiles().await.unwrap()
    }

    async fn profile_count(storage: &AskarStorage, profile: &str) -> usize {
        all_profiles(storage)
            .await
            .iter()
            .filter(|name| name.as_str() == profile)
            .count()
    }
}
