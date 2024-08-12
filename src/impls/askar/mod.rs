pub mod kms;

use aries_askar::kms::LocalKey;
use aries_askar::storage::KdfMethod;
use aries_askar::{Error, PassKey, Store, StoreKeyMethod};

#[derive(Debug, Clone)]
pub struct AskarStorage(Store, Option<String>);

const IN_MEMORY_DB_URL: &str = "sqlite://:memory:";

impl AskarStorage {
    pub async fn create(pass_key: &str, profile: Option<String>) -> Result<AskarStorage, Error> {
        let key_method = StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()));
        let pass_key = PassKey::from(pass_key);

        let store = Store::provision(
            IN_MEMORY_DB_URL,
            key_method,
            pass_key,
            profile.clone(),
            true,
        )
        .await?;

        Ok(AskarStorage(store, profile))
    }

    pub async fn open(pass_key: &str, profile: Option<String>) -> Result<AskarStorage, Error> {
        let key_method = StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()));
        let pass_key = PassKey::from(pass_key);

        let store = Store::open(
            IN_MEMORY_DB_URL,
            Some(key_method),
            pass_key,
            profile.clone(),
        )
        .await?;

        Ok(AskarStorage(store, profile))
    }

    pub async fn close(&self) -> Result<(), Error> {
        self.0.to_owned().close().await
    }

    pub(crate) async fn insert_key(&self, key_id: &str, key: &LocalKey) -> Result<(), Error> {
        let mut session = self.0.session(self.1.clone()).await?;
        session.insert_key(key_id, &key, None, None, None).await?;
        session.commit().await?;

        Ok(())
    }

    pub(crate) async fn get_key(&self, key_id: &str) -> Result<Option<LocalKey>, Error> {
        let mut session = self.0.session(self.1.clone()).await?;

        session
            .fetch_key(key_id, false)
            .await?
            .map(|key_entry| key_entry.load_local_key())
            .transpose()
    }
}
