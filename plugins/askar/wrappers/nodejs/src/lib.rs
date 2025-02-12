mod kms;
mod vault;

use napi::{Error, Result};
use napi_derive::napi;

#[napi]
#[derive(Debug, Clone)]
pub struct AskarStorage(askar::AskarStorage);

#[napi(object)]
pub struct AskarStorageConfig {
    pub db_url: String,
    pub key_method: KeyMethod,
    pub pass_key: String,
    pub profile: String,
}

#[napi]
pub enum KeyMethod {
    DeriveKey,
    RawKey,
    Unprotected,
}

#[napi]
impl AskarStorage {
    #[napi]
    pub async fn create(config: AskarStorageConfig, recreate: bool) -> Result<Self> {
        let storage = askar::AskarStorage::create(&config.into(), recreate)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Self(storage))
    }

    #[napi]
    pub async fn open(config: AskarStorageConfig) -> Result<Self> {
        let storage = askar::AskarStorage::open(&config.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Self(storage))
    }

    #[napi]
    pub async fn remove(db_url: String) -> Result<bool> {
        let removed = askar::AskarStorage::remove(&db_url)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(removed)
    }

    #[allow(clippy::missing_safety_doc)]
    #[napi]
    pub async unsafe fn close(&mut self) -> Result<()> {
        self.0
            .to_owned()
            .close()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(())
    }

    #[napi]
    pub async fn create_profile(&self, profile: String) -> Result<String> {
        let profile = self
            .0
            .create_profile(profile)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(profile)
    }

    #[napi]
    pub fn get_active_profile(&self) -> String {
        self.0.get_active_profile()
    }

    #[allow(clippy::missing_safety_doc)]
    #[napi]
    pub async unsafe fn change_active_profile(&mut self, profile: String) -> Result<()> {
        self.0
            .to_owned()
            .change_active_profile(profile)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(())
    }

    #[napi]
    pub async fn remove_profile(&self, profile: String) -> Result<bool> {
        let is_removed = self
            .0
            .remove_profile(profile)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(is_removed)
    }
}

impl From<KeyMethod> for askar::KeyMethod {
    fn from(value: KeyMethod) -> Self {
        match value {
            KeyMethod::DeriveKey => askar::KeyMethod::DeriveKey,
            KeyMethod::RawKey => askar::KeyMethod::RawKey,
            KeyMethod::Unprotected => askar::KeyMethod::Unprotected,
        }
    }
}

impl From<AskarStorageConfig> for askar::AskarStorageConfig {
    fn from(value: AskarStorageConfig) -> Self {
        askar::AskarStorageConfig {
            db_url: value.db_url,
            key_method: value.key_method.into(),
            pass_key: value.pass_key,
            profile: value.profile,
        }
    }
}
