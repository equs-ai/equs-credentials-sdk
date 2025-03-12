mod kms;
mod vault;

use napi::{Error, Result};
use napi_derive::napi;

/// `Askar Storage`
///
/// A wrapper around the native Askar storage functionality.
///
/// Provides methods for creating, opening, and managing storage instances
/// and profiles for secure credential storage.
///
/// @method create - {@link AskarStorage.create}
/// @method open - {@link AskarStorage.open}
/// @method remove - {@link AskarStorage.remove}
/// @method close - {@link AskarStorage.close}
/// @method create_profile - {@link AskarStorage.create_profile}
/// @method get_active_profile - {@link AskarStorage.get_active_profile}
/// @method change_active_profile - {@link AskarStorage.change_active_profile}
/// @method remove_profile - {@link AskarStorage.remove_profile}
#[napi]
#[derive(Debug, Clone)]
pub struct AskarStorage(askar::AskarStorage);

/// `Askar Storage Configuration`
///
/// Configuration options for initializing Askar storage.
///
/// Provides necessary parameters to establish a connection to an Askar database.
///
/// @property db_url - Database URL for Askar storage
/// @property key_method - Method used for key protection {@link KeyMethod}
/// @property pass_key - Passphrase or raw key material used with the specified key method
/// @property profile - Name of the profile/namespace within the storage
#[napi(object)]
pub struct AskarStorageConfig {
    pub db_url: String,
    pub key_method: KeyMethod,
    pub pass_key: String,
    pub profile: String,
}

/// `Key Protection Method`
///
/// Specifies how encryption keys for the Askar storage are protected.
///
/// Determines how the pass_key value is processed when opening or creating storage.
///
/// @value DeriveKey - Derives encryption key from the provided passphrase
/// @value RawKey - Uses the provided key material directly
/// @value Unprotected - Minimal key protection, suitable for testing environments only
#[napi]
pub enum KeyMethod {
    DeriveKey,
    RawKey,
    Unprotected,
}

#[napi]
impl AskarStorage {
    /// Provision a new store instance using a config
    ///
    /// Creates and initializes a new Askar storage instance with the provided configuration.
    ///
    /// @param config - Configuration for the storage instance {@link AskarStorageConfig}
    /// @param recreate - If true, recreates the storage if it already exists
    /// @returns A new AskarStorage instance
    #[napi]
    pub async fn create(config: AskarStorageConfig, recreate: bool) -> Result<Self> {
        let storage = askar::AskarStorage::create(&config.into(), recreate)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Self(storage))
    }

    /// Open a store instance by using a config
    ///
    /// Opens an existing Askar storage instance with the provided configuration.
    ///
    /// @param config - Configuration for the storage instance {@link AskarStorageConfig}
    /// @returns An opened AskarStorage instance
    #[napi]
    pub async fn open(config: AskarStorageConfig) -> Result<Self> {
        let storage = askar::AskarStorage::open(&config.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(Self(storage))
    }

    /// Remove a store instance using a database URL
    ///
    /// Deletes an Askar storage instance at the specified location.
    ///
    /// @param db_url - Database URL pointing to the storage location
    /// @returns Boolean indicating whether the storage was successfully removed
    #[napi]
    pub async fn remove(db_url: String) -> Result<bool> {
        let removed = askar::AskarStorage::remove(&db_url)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(removed)
    }

    /// Close the store instance, waiting for any shutdown procedures to complete.
    ///
    /// Safely closes the storage instance and releases any resources.
    /// This operation is unsafe as it may affect other references to the storage.
    ///
    /// @returns void if successful
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

    /// Create a new profile with the given profile name
    ///
    /// Creates a new namespace within the storage for organizing credentials.
    ///
    /// @param profile - Name for the new profile to create
    /// @returns The name of the created profile
    #[napi]
    pub async fn create_profile(&self, profile: String) -> Result<String> {
        let profile = self
            .0
            .create_profile(profile)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(profile)
    }

    /// Create an active profile to store instance
    ///
    /// Retrieves the name of the currently active profile.
    ///
    /// @returns Name of the active profile
    #[napi]
    pub fn get_active_profile(&self) -> String {
        self.0.get_active_profile()
    }

    /// Change an active profile against store instance
    ///
    /// Switches the active profile to a different existing profile.
    /// This operation is unsafe as it may affect other references to the storage.
    ///
    /// @param profile - Name of the profile to switch to
    /// @returns Nothing if successful
    #[allow(clippy::missing_safety_doc)]
    #[napi]
    pub async unsafe fn change_active_profile(&mut self, profile: String) -> Result<()> {
        self.0
            .change_active_profile(profile)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(())
    }

    /// Remove an existing profile with the given profile name
    ///
    /// Deletes a profile and all associated data from the storage.
    ///
    /// @param profile - Name of the profile to remove
    /// @returns Boolean indicating whether the profile was successfully removed
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
