//! Delegate SD-JWT grant (dSD-JWT).
//!
//! Gated behind this crate's `delegate-sd-jwt` feature, which forwards to the
//! SDK feature of the same name — the chain machinery does not exist without it.
//!
//! A delegation hop is signed by the key the credential is bound to, so this
//! builder drives `vc::core::HolderService::create_delegated_credential`, the
//! only public path that appends one.

use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::inmem::vault::InMemVault;
use equs_sdk::nonce::Nonce;
use equs_sdk::vault::CredentialEntry;
use equs_sdk::vc::core::{
    Holder, HolderBinder, HolderMetadata, HolderService, ProofOfPossessionMetadata,
};
use equs_sdk::vc::{ChainBindingMode, Credential, DelegationParams};
use serde_json::{Map, Value};
use std::sync::Arc;

use crate::claims::{DEFAULT_AUDIENCE, DEFAULT_CLIENT_ID, DEFAULT_NONCE};
use crate::error::{Error, Result};
use crate::http::StaticHttpClient;
use crate::keys::FixtureKey;

/// Builder for a delegated SD-JWT grant.
///
/// `aud` and `nonce` are written into every delegate payload, and are what the
/// verifier compares on the final hop.
pub struct DsdJwt<'a> {
    kms: &'a LocalKms,
    holder: &'a FixtureKey,
    credential: String,
    payloads: Vec<Value>,
    claims_to_disclose: Option<Map<String, Value>>,
    binding: ChainBindingMode,
    audience: String,
    nonce: String,
}

impl<'a> DsdJwt<'a> {
    /// Starts a delegation over `credential`, held by `holder` in `kms`.
    #[must_use]
    pub fn builder(
        kms: &'a LocalKms,
        holder: &'a FixtureKey,
        credential: impl Into<String>,
    ) -> Self {
        Self {
            kms,
            holder,
            credential: credential.into(),
            payloads: vec![serde_json::json!({ "scope": "purchase" })],
            claims_to_disclose: Some(Map::new()),
            binding: ChainBindingMode::SdHash,
            audience: DEFAULT_AUDIENCE.to_string(),
            nonce: DEFAULT_NONCE.to_string(),
        }
    }

    /// Replaces the delegate payloads — the alternatives this hop offers.
    #[must_use]
    pub fn payloads(mut self, payloads: Vec<Value>) -> Self {
        self.payloads = payloads;
        self
    }

    /// Sets which of the credential's claims travel with the grant.
    #[must_use]
    pub fn claims_to_disclose(mut self, claims: Option<Map<String, Value>>) -> Self {
        self.claims_to_disclose = claims;
        self
    }

    /// Sets how the hop binds to the credential beneath it.
    #[must_use]
    pub fn binding(mut self, binding: ChainBindingMode) -> Self {
        self.binding = binding;
        self
    }

    /// Sets the `aud` written into every delegate payload.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Sets the `nonce` written into every delegate payload.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// The holder binding this grant is built against.
    #[must_use]
    pub fn holder_binder(&self) -> HolderBinder {
        HolderBinder {
            nonce: Nonce::from_secret(self.nonce.clone()),
            verifier_id: self.audience.clone(),
            response_uri: None,
        }
    }

    /// Signs the delegation hop and returns the compact grant.
    ///
    /// # Errors
    ///
    /// * [`Error::Sdk`] — the holder service rejected the credential or the
    ///   payloads, or signing failed.
    pub async fn build(self) -> Result<String> {
        let holder = HolderService::new(
            self.kms.clone(),
            InMemVault::new(),
            HolderMetadata {
                client_id: DEFAULT_CLIENT_ID.to_string(),
                pop: ProofOfPossessionMetadata::default(),
            },
            equs_sdk::did::universal::UniversalResolver::default(),
            Arc::new(StaticHttpClient::new()),
        );

        let entry = CredentialEntry {
            credential: Credential::SdJwt(self.credential),
            kid: self.holder.kid.clone(),
            id: "fixture-credential".to_string(),
        };

        holder
            .create_delegated_credential(
                &entry,
                DelegationParams {
                    delegate_payloads: self.payloads,
                    claims_to_disclose: self.claims_to_disclose,
                    drop_disclosures: None,
                    binding: self.binding,
                    aud: Some(self.audience),
                    nonce: Some(self.nonce),
                },
            )
            .await
            .map_err(|e| Error::Sdk {
                details: e.to_string(),
            })
    }
}
