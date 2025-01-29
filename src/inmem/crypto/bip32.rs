use crate::crypto;
use crate::crypto::{DerivationSnafu, KeyGenerationSnafu};
use crate::inmem::crypto::k256::K256;
use bip32::{DerivationPath, XPrv};
use std::str::FromStr;
use tracing::{instrument, Level};

#[derive(Clone)]
pub struct Bip32 {
    seed: Vec<u8>,
}

impl Bip32 {
    /// Creates a BIP32 from a seed key.
    ///
    /// # Arguments
    ///
    /// * `seed` - a seed value.
    ///
    /// # Returns
    ///
    /// A derivation suite for the provided seed.
    #[instrument(level = Level::TRACE, skip_all)]
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
        }
    }

    /// Returns the corresponding `Suite` for signing/verification.
    ///
    /// # Returns
    ///
    /// A crypto `Suite`.
    #[instrument(level = Level::TRACE, skip_all, err())]
    pub fn suite(&self) -> crypto::Result<K256> {
        let key = XPrv::new(&self.seed).map_err(|e| {
            KeyGenerationSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        Ok(K256::new(key.private_key().to_owned()))
    }

    /// Derives a key for specified path.
    ///
    /// # Arguments
    ///
    /// * `path` - a derivation path.
    ///
    /// # Returns
    ///
    /// Private key bytes.
    ///
    /// # Errors
    ///
    /// * [crypto::Error::Derivation] - fails to derive a key.
    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    pub async fn derive(&self, path: &str) -> crypto::Result<Vec<u8>> {
        let derivation_path = DerivationPath::from_str(path).map_err(|err| {
            DerivationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        XPrv::derive_from_path(&self.seed, &derivation_path)
            .map_err(|err| {
                DerivationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
            .map(|k| k.to_bytes().to_vec())
    }
}
