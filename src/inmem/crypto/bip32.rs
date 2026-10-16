use crate::crypto;
use crate::crypto::{DerivationSnafu, KeyGenerationSnafu};
use crate::inmem::crypto::k256::K256;
use bip32::{DerivationPath, XPrv};
use std::str::FromStr;
use tracing::{Level, instrument};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key;

    // BIP32 (RFC + bip32 crate) accepts only 16-, 32-, or 64-byte seeds.
    fn valid_seed() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn from_seed_stores_seed_bytes_verbatim() {
        let seed = valid_seed();
        let bip32 = Bip32::from_seed(&seed);

        assert_eq!(bip32.seed, seed);
    }

    #[test]
    fn suite_returns_k256_with_32_byte_private_key_for_valid_seed() {
        let bip32 = Bip32::from_seed(&valid_seed());

        let suite = bip32.suite().unwrap();

        assert_eq!(suite.private_key().unwrap().len(), 32);
    }

    #[test]
    #[should_panic(expected = "Key generation error")]
    fn suite_rejects_seed_with_invalid_length() {
        // bip32 only accepts seed lengths of 16, 32, or 64 bytes; 4 fails.
        let bip32 = Bip32::from_seed(&[1u8; 4]);

        bip32.suite().unwrap();
    }

    #[tokio::test]
    async fn derive_returns_32_byte_private_key_for_valid_path() {
        let bip32 = Bip32::from_seed(&valid_seed());

        let bytes = bip32.derive("m/0'/0").await.unwrap();

        assert_eq!(bytes.len(), 32);
    }

    #[tokio::test]
    async fn derive_produces_different_keys_for_different_paths() {
        let bip32 = Bip32::from_seed(&valid_seed());

        let a = bip32.derive("m/0'/0").await.unwrap();
        let b = bip32.derive("m/0'/1").await.unwrap();

        assert_ne!(a, b);
    }

    #[tokio::test]
    #[should_panic(expected = "Derivation error")]
    async fn derive_rejects_malformed_path() {
        let bip32 = Bip32::from_seed(&valid_seed());

        bip32.derive("not a valid path").await.unwrap();
    }
}
