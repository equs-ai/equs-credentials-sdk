//! Key material for fixtures, always minted through [`LocalKms`].
//!
//! No builder in this crate ever holds raw key material: a [`FixtureKey`] is a
//! `did:key` plus the KMS key id and the [`KeyHandle`] the KMS handed back, and
//! every signature goes through that handle's [`equs_sdk::crypto::Signer`] impl.

use equs_sdk::did::didkey::DIDKey;
use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::did::{DID, DIDBuf, DIDResolver, DIDURLBuf};
use equs_sdk::inmem::kms::{KeyHandle, LocalKms};
use equs_sdk::kms::{CreateOptions, KeyID, KeyType, Kms};
use equs_sdk::vc::core::KeyMetadata;

use crate::error::{Error, Result};

/// A KMS-held key together with the `did:key` identifiers derived from it.
///
/// Covers every [`KeyType`] the SDK supports — `Ed25519`, `P256`, `K256` and
/// `Bls12381`.
#[derive(Clone)]
pub struct FixtureKey {
    /// The KMS key id the handle was created under.
    pub kid: KeyID,
    /// The `did:key` DID derived from the public key.
    pub did: DID,
    /// The first verification method URL of that DID.
    pub did_url: DIDURLBuf,
    /// The KMS key handle; signs through [`equs_sdk::crypto::Signer`].
    pub handle: KeyHandle,
}

impl FixtureKey {
    /// Creates a key of `key_type` in `kms` and resolves its `did:key`.
    ///
    /// # Errors
    ///
    /// * [`crate::Error::Kms`] — the KMS could not create the key.
    /// * [`crate::Error::Did`] — the `did:key` could not be generated or resolved.
    pub async fn create(kms: &LocalKms, key_type: KeyType) -> Result<Self> {
        let (kid, handle) = kms
            .create_and_handle(key_type, CreateOptions::default())
            .await
            .map_err(|e| Error::Kms {
                details: e.to_string(),
            })?;

        let did = DIDKey::generate(handle.clone()).map_err(|e| Error::Did {
            details: e.to_string(),
        })?;

        let did_buf = DIDBuf::from_string(did.clone()).map_err(|e| Error::Did {
            details: format!("{e:?}"),
        })?;

        let did_url = UniversalResolver::default()
            .resolve_into_any_verification_method(did_buf.as_did())
            .await
            .map_err(|e| Error::Did {
                details: e.to_string(),
            })?
            .ok_or_else(|| Error::Did {
                details: "did:key resolved to no verification method".to_string(),
            })?
            .id;

        Ok(Self {
            kid,
            did,
            did_url,
            handle,
        })
    }

    /// Creates a `P256` key — the default for fixtures that do not care.
    ///
    /// # Errors
    ///
    /// See [`FixtureKey::create`].
    pub async fn create_default(kms: &LocalKms) -> Result<Self> {
        Self::create(kms, KeyType::P256).await
    }

    /// The `KeyMetadata` the SDK services take for this key.
    #[must_use]
    pub fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            kid: self.kid.clone(),
            did_url: self.did_url.to_string(),
        }
    }
}
