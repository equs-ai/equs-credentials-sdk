use tracing::{instrument, Level};

type Level_ = Level;

use crate::did::{DidGenerationSnafu, KeyNotSupportedSnafu, Result, DID};
use crate::{crypto, did};

pub type Error = did::Error;

/// A general `did:key` service.
///
/// Supports generation of `did:keys`.
pub struct DIDKey {}

impl DIDKey {
    /// Create a `did:key`.
    ///
    /// # Arguments
    ///
    /// * `key` - a key to include in `did:key`.
    ///
    /// # Returns
    ///
    /// A new `did:key` based on the `key` on success.
    ///
    /// # Errors
    ///
    /// * [Error::KeyNotSupported] - fails if the `jwk` is not supported for `key`.
    /// * [Error::DidGeneration] - can't generate `DID`.
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    pub fn generate<K>(key: K) -> Result<DID>
    where
        K: crypto::Key,
    {
        let jwk = key
            .jwk()
            .ok_or_else(|| KeyNotSupportedSnafu { type_: "jwk" }.build())?;

        let did = ssi::dids::key::DIDKey::generate(&jwk);
        let result = did.map(|did| did.to_string()).map_err(|e| {
            DidGenerationSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::did::didkey::DIDKey;
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{CreateOptions, Kms};
    use crate::utils::test_utils::no_jwk_key;

    const SAMPLE_DID: &str = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6";
    const SAMPLE_DID_URL: &str = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6";

    #[tokio::test]
    async fn didkey_generated_correctly() {
        let kms = LocalKms::new();

        for kt in kms::SUPPORTED_KEYS {
            let (_, kh) = kms.create_and_handle(kt, CreateOptions {}).await.unwrap();

            let did = DIDKey::generate(kh.clone()).unwrap();
            assert!(did.starts_with("did:key:"));
        }
    }

    #[tokio::test]
    async fn didkey_generate_fails_on_invalid_jwk() {
        assert!(DIDKey::generate(no_jwk_key()).is_err());
    }
}
