//! SD-JWT VP with a key-binding JWT (`typ: kb+jwt`) appended.
//!
//! A KB-JWT's `sd_hash` is a digest over the exact credential and disclosure
//! set it is presented with, so it cannot be built independently of them. This
//! builder therefore drives the SDK's `vc::core::HolderService`, which is the
//! only public path that appends one.

use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::inmem::vault::InMemVault;
use equs_sdk::nonce::Nonce;
use equs_sdk::vault::CredentialEntry;
use equs_sdk::vc::core::{
    Holder, HolderBinder, HolderMetadata, HolderService, PresentationInput,
    ProofOfPossessionMetadata,
};
use equs_sdk::vc::{Credential, Presentation};
use std::sync::Arc;

use crate::claims::{DEFAULT_AUDIENCE, DEFAULT_CLIENT_ID, DEFAULT_NONCE};
use crate::error::{Error, Result};
use crate::http::StaticHttpClient;
use crate::keys::FixtureKey;

/// Builder for an SD-JWT VP carrying a key-binding JWT.
///
/// `nonce` and `verifier_id` are what the KB-JWT binds to, and are what a
/// verifier compares; both default and both are overridable.
pub struct KbJwt<'a> {
    kms: &'a LocalKms,
    holder: &'a FixtureKey,
    credential: String,
    nonce: String,
    verifier_id: String,
    response_uri: Option<String>,
    disclosed: Vec<String>,
}

impl<'a> KbJwt<'a> {
    /// Starts a presentation of `credential`, held by `holder` in `kms`.
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
            nonce: DEFAULT_NONCE.to_string(),
            verifier_id: DEFAULT_AUDIENCE.to_string(),
            response_uri: None,
            disclosed: vec!["name".to_string()],
        }
    }

    /// Sets the nonce the KB-JWT binds to.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Sets the `aud` of the KB-JWT — the verifier it is addressed to.
    #[must_use]
    pub fn verifier_id(mut self, verifier_id: impl Into<String>) -> Self {
        self.verifier_id = verifier_id.into();
        self
    }

    /// Sets the response URI carried in the holder binding.
    #[must_use]
    pub fn response_uri(mut self, response_uri: impl Into<String>) -> Self {
        self.response_uri = Some(response_uri.into());
        self
    }

    /// Sets which claim names are disclosed in the presentation.
    #[must_use]
    pub fn disclosed(mut self, disclosed: Vec<String>) -> Self {
        self.disclosed = disclosed;
        self
    }

    /// The holder binding this presentation is built against.
    ///
    /// A verifier is handed the same value, so a round-trip test does not have
    /// to restate the nonce and audience.
    #[must_use]
    pub fn holder_binder(&self) -> HolderBinder {
        HolderBinder {
            nonce: Nonce::from_secret(self.nonce.clone()),
            verifier_id: self.verifier_id.clone(),
            response_uri: self.response_uri.clone(),
        }
    }

    /// Creates the presentation and returns the compact SD-JWT VP.
    ///
    /// # Errors
    ///
    /// * [`Error::Sdk`] — the holder service rejected the credential or the
    ///   signature failed.
    pub async fn build(self) -> Result<String> {
        let binder = self.holder_binder();

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

        let input = PresentationInput {
            id: "fixture-presentation".to_string(),
            format: None,
            restrictions: self
                .disclosed
                .iter()
                .map(|name| equs_sdk::vc::core::PresentationRestriction {
                    fields: vec![format!("$.{name}")],
                    value: None,
                    optional: false,
                })
                .collect(),
        };

        let presentation = holder
            .create_presentation(Some(binder), &input, &entry)
            .await
            .map_err(|e| Error::Sdk {
                details: e.to_string(),
            })?;

        match presentation {
            Presentation::SdJwtVp(vp) => Ok(vp),
            other => Err(Error::Sdk {
                details: format!("holder produced a non-SD-JWT presentation: {other:?}"),
            }),
        }
    }
}
