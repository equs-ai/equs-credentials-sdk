use aries_askar::storage::KdfMethod;
use aries_askar::{Error, PassKey, Store, StoreKeyMethod};
use tracing::{instrument, Level};

use crate::askar::kms::AskarKms;
use crate::askar::vault::AskarVault;

pub mod kms;
pub mod vault;

#[derive(Debug)]
pub struct AskarStorage(Store);

const IN_MEMORY_DB_URL: &str = "sqlite://:memory:";

impl AskarStorage {
    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
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

        Ok(AskarStorage(store))
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
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

        Ok(AskarStorage(store))
    }

    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    pub fn kms(&self) -> AskarKms {
        AskarKms::new(self.0.clone())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(level = Level::TRACE)
    )]
    pub fn vault(&self) -> AskarVault {
        AskarVault::new(self.0.clone())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE)
    )]
    pub async fn close(self) -> Result<(), Error> {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests {
    use crate::askar::AskarStorage;
    use crate::kms::test_util::test_kms;
    use crate::vault::test_util::test_vault;

    #[tokio::test]
    async fn test_askar_kms() {
        let storage = AskarStorage::create("sEcrEt", Some("Askar-Wallet".to_string()))
            .await
            .unwrap();
        let kms = storage.kms();
        test_kms(kms).await;
        storage.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_askar_vault() {
        let storage = AskarStorage::create("sEcrEt", Some("Askar-Wallet".to_string()))
            .await
            .unwrap();
        let vault = storage.vault();
        test_vault(vault).await;
        storage.close().await.unwrap();
    }
}
