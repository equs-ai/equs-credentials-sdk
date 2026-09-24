//! Encrypted OID4VP response (JWE).
//!
//! Not a JWT, but it shares the key plumbing and is easy to get wrong by hand,
//! so it is built here too. Encryption goes through the SDK's own
//! `JweEncryptor`; the matching decryption is `LocalKms::decrypt`, which every
//! `Kms` gets from the blanket `JweDecrypt` impl.
//!
//! ECDH-ES is the only key management the encryptor supports, so the recipient
//! key must be `P256`.

use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::kms::Kms;
use equs_sdk::vc::oid4vp::ClientMetadata;
use equs_sdk::vc::oid4vp::jwe::JweEncryptor;
use serde_json::Value;

use crate::error::{Error, Result};
use equs_sdk::crypto::Key;

/// Default content encryption algorithm for fixtures.
pub const DEFAULT_ENC: &str = "A256GCM";

/// Builder for a compact JWE addressed to a KMS-held recipient key.
pub struct Jwe<'a> {
    kms: &'a LocalKms,
    recipient_kid: String,
    enc: String,
    payload: Value,
}

impl<'a> Jwe<'a> {
    /// Starts a JWE addressed to `recipient_kid`, a `P256` key in `kms`.
    #[must_use]
    pub fn builder(kms: &'a LocalKms, recipient_kid: impl Into<String>) -> Self {
        Self {
            kms,
            recipient_kid: recipient_kid.into(),
            enc: DEFAULT_ENC.to_string(),
            payload: serde_json::json!({ "vp_token": "fixture" }),
        }
    }

    /// Sets the content encryption algorithm: `A256GCM`, `A128GCM` or
    /// `A128CBC-HS256`.
    #[must_use]
    pub fn enc(mut self, enc: impl Into<String>) -> Self {
        self.enc = enc.into();
        self
    }

    /// Sets the plaintext payload.
    #[must_use]
    pub fn payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    /// Encrypts the payload and returns the compact JWE.
    ///
    /// # Errors
    ///
    /// * [`Error::Kms`] — the recipient key is unknown.
    /// * [`Error::Signing`] — the recipient key exposes no JWK.
    /// * [`Error::Json`] — the recipient metadata could not be assembled.
    /// * [`Error::Sdk`] — the encryptor rejected the key or the payload.
    pub async fn build(self) -> Result<String> {
        let handle = self
            .kms
            .get(&self.recipient_kid)
            .await
            .map_err(|e| Error::Kms {
                details: e.to_string(),
            })?;

        let mut public_jwk = handle
            .jwk()
            .ok_or_else(|| Error::Signing {
                details: "recipient key exposes no JWK".to_string(),
            })?
            .to_public();
        public_jwk.key_id = Some(self.recipient_kid.clone());

        let mut jwk_map = match serde_json::to_value(&public_jwk).map_err(|e| Error::Json {
            details: e.to_string(),
        })? {
            Value::Object(map) => map,
            other => {
                return Err(Error::Json {
                    details: format!("recipient JWK is not an object: {other}"),
                });
            }
        };
        jwk_map.insert("alg".to_string(), Value::from("ECDH-ES"));

        let metadata: ClientMetadata = serde_json::from_value(serde_json::json!({
            "jwks": { "keys": [jwk_map] },
            "encrypted_response_enc_values_supported": [self.enc],
        }))
        .map_err(|e| Error::Json {
            details: e.to_string(),
        })?;

        JweEncryptor::new(metadata)
            .encrypt(self.payload)
            .await
            .map_err(|e| Error::Sdk {
                details: e.to_string(),
            })
    }
}
