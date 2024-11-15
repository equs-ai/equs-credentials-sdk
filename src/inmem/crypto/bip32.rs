use crate::crypto::{DerivationSnafu, Result};
use crate::crypto::{DerivationSuite, KeyGenerationSnafu};
use crate::inmem::crypto::k256::K256;
use async_trait::async_trait;
use bip32::{DerivationPath, XPrv};
use std::str::FromStr;
use tracing::{instrument, Level};

#[derive(Clone)]
pub struct Bip32 {
    seed: Vec<u8>,
}

#[async_trait]
impl DerivationSuite<K256> for Bip32 {
    #[instrument(level = Level::TRACE, skip_all)]
    fn from_seed(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    fn suite(&self) -> Result<K256> {
        let key = XPrv::new(&self.seed).map_err(|e| {
            KeyGenerationSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        Ok(K256::new(key.private_key().to_owned()))
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    async fn derive(&self, path: &str) -> Result<Vec<u8>> {
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
