//! JWE decryption using [`Kms`]-held keys.
//!
//! This module owns the generic JWE **decryption** path: given a compact JWE
//! and a [`Kms`], it looks up the key referenced by the JWE header and decrypts
//! the payload. It is intentionally protocol-agnostic — OID4VP response
//! encryption (the [`crate::vc::oid4vp::jwe`] module) builds on these types but
//! this module knows nothing about OID4VP.
//!
//! The decryption never exports private key material. The recipient key stays
//! inside the KMS; only the *shared secret* is derived, via the key's
//! [`KeyAgreement`] capability (the KMS performs the ECDH internally, exactly
//! as a remote KMS's `DeriveSharedSecret` would). one_core then runs the
//! Concat-KDF and AEAD over that shared secret.
//!
//! A [`Kms`] opts into decryption by having its [`KeyHandle`] implement
//! [`KeyAgreement`]; that unlocks blanket impls of both [`JweDecrypt`] (JSON)
//! and [`crate::kms::JweDecryptBytes`] (raw bytes).
//!
//! **Native-only implementation.** The bridge to one_core's
//! `PrivateKeyAgreementHandle` requires `Send` futures, but the wasm
//! [`KeyAgreement`] capability is `?Send`; the two cannot be reconciled and the
//! wasm target never drives JWE decryption. So everything except the
//! [`JweDecrypt`] trait *declaration* (kept for use as a generic bound in
//! `vc::oid4vp`) is gated to `#[cfg(not(target_arch = "wasm32"))]`.

use crate::crypto;
use crate::kms::{self, KeyHandle};
use async_trait::async_trait;
use one_core_portable::one_crypto::encryption::EncryptionError;
use serde_json::Value;
use snafu::{Location, Snafu};

// The KMS-backed decryption path bridges to one_core's `PrivateKeyAgreementHandle`,
// which requires `Send` futures, whereas the wasm `KeyAgreement` capability is
// `?Send`. The two are irreconcilable on wasm, and the wasm target never drives
// JWE decryption, so the whole implementation is native-only. The `JweDecrypt`
// trait declaration below stays on every target because `vc::oid4vp` uses it as a
// bound in generic code.
#[cfg(not(target_arch = "wasm32"))]
use crate::kms::{JweDecryptBytes, KeyAgreement, Kms};
#[cfg(not(target_arch = "wasm32"))]
use one_core_portable::one_crypto::jwe::{PrivateKeyAgreementHandle, decrypt_jwe_payload};
#[cfg(not(target_arch = "wasm32"))]
use one_core_portable::one_crypto::signer::ecdsa::ECDSASigner;
#[cfg(not(target_arch = "wasm32"))]
use one_core_portable::one_crypto::signer::eddsa::EDDSASigner;
#[cfg(not(target_arch = "wasm32"))]
use one_core_portable::standardized_types::jwk::PublicJwk;
#[cfg(not(target_arch = "wasm32"))]
use p256::SecretKey;
#[cfg(not(target_arch = "wasm32"))]
use secrecy::SecretSlice;
#[cfg(not(target_arch = "wasm32"))]
use snafu::ResultExt;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum JweDecryptError {
    #[snafu(display("{source}"))]
    Kms {
        source: kms::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Encryption {
        source: EncryptionError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Crypto {
        source: crypto::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Parsing {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

/// Decrypt a JWE with a [`Kms`]-held key, returning the parsed JSON payload.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait JweDecrypt<KH: KeyHandle> {
    async fn decrypt(&self, jwe: &str, kid: &str) -> Result<Value, JweDecryptError>;
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl<KH: KeyHandle + KeyAgreement + Send + Sync, KMS: Kms<KH>> JweDecrypt<KH> for KMS {
    async fn decrypt(&self, jwe: &str, kid: &str) -> Result<Value, JweDecryptError> {
        decrypt_jwe(self, jwe, kid).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl<KH: KeyHandle + KeyAgreement + Send + Sync, KMS: Kms<KH>> JweDecryptBytes<KH> for KMS {
    async fn decrypt_bytes(&self, jwe: &str, kid: &str) -> Result<Vec<u8>, JweDecryptError> {
        decrypt_jwe_bytes(self, jwe, kid).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn decrypt_jwe<KH: KeyHandle + KeyAgreement + Send + Sync, KMS: Kms<KH>>(
    kms: &KMS,
    jwe: &str,
    kid: &str,
) -> Result<Value, JweDecryptError> {
    let decoded = decrypt_jwe_bytes(kms, jwe, kid).await?;
    serde_json::from_slice(decoded.as_slice()).context(ParsingSnafu {})
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn decrypt_jwe_bytes<KH: KeyHandle + KeyAgreement + Send + Sync, KMS: Kms<KH>>(
    kms: &KMS,
    jwe: &str,
    kid: &str,
) -> Result<Vec<u8>, JweDecryptError> {
    let kh = kms.get(&kid.to_string()).await.context(KmsSnafu {})?;

    // The KMS derives the shared secret against the stored key; the private key
    // never leaves it. one_core then runs the Concat-KDF and AEAD.
    let handle = KeyAgreementAdapter(kh);
    let decoded = decrypt_jwe_payload(jwe, &handle)
        .await
        .context(EncryptionSnafu {})?;

    Ok(decoded)
}

/// Bridges a [`KeyAgreement`]-capable [`KeyHandle`] to one_core's
/// [`PrivateKeyAgreementHandle`], serializing the remote JWK back to JSON for
/// the KMS to consume.
#[cfg(not(target_arch = "wasm32"))]
struct KeyAgreementAdapter<KH>(KH);

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl<KH: KeyAgreement + Send + Sync> PrivateKeyAgreementHandle for KeyAgreementAdapter<KH> {
    async fn shared_secret(
        &self,
        remote_jwk: &PublicJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        let jwk_json = serde_json::to_string(remote_jwk)
            .map_err(|e| EncryptionError::Crypto(format!("Failed to serialize remote JWK: {e}")))?;
        let secret = self
            .0
            .shared_secret(&jwk_json)
            .await
            .map_err(|e| EncryptionError::Crypto(format!("Key agreement failed: {e}")))?;
        Ok(SecretSlice::from(secret))
    }
}

/// Test scaffolding: a [`PrivateKeyAgreementHandle`] backed by a raw Ed25519
/// private key. Used by encrypt/decrypt round-trip tests that hold a known JWK;
/// not part of the KMS decryption path.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct WrapperForEdDSAHandle {
    pub key: ed25519_compact::SecretKey,
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl PrivateKeyAgreementHandle for WrapperForEdDSAHandle {
    async fn shared_secret(
        &self,
        remote_jwk: &PublicJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        EDDSASigner::shared_secret_x25519(&self.key.to_vec().into(), remote_jwk)
    }
}

/// Test scaffolding: a [`PrivateKeyAgreementHandle`] backed by a raw P-256
/// private key. See [`WrapperForEdDSAHandle`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct WrapperForES256Handle {
    pub key: SecretKey,
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl PrivateKeyAgreementHandle for WrapperForES256Handle {
    async fn shared_secret(
        &self,
        remote_jwk: &PublicJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        ECDSASigner::shared_secret_p256(&self.key.to_bytes().to_vec().into(), remote_jwk)
    }
}
