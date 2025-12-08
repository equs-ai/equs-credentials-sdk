use aries_askar::entry::{Entry, TagFilter};
use aries_askar::storage::KdfMethod;
use aries_askar::storage::backend::OrderBy;
use aries_askar::{Error, PassKey, Session, Store, StoreKeyMethod};
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

    /// Create a new profile with the given profile name
    #[instrument(level = Level::TRACE, err(), ret())]
    pub async fn create_profile(&self, profile: String) -> Result<String> {
        self.store.create_profile(Some(profile)).await
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
