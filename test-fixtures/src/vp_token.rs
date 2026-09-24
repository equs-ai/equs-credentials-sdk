//! OID4VP `vp_token`.
//!
//! A `vp_token` is not itself a JWT: it is the JSON value carrying one or more
//! presentations, keyed by DCQL credential id or given as a bare string. The
//! presentations inside it are SD-JWT VPs, so this builder composes
//! [`crate::kb_jwt::KbJwt`] rather than signing anything of its own.

use serde_json::{Map, Value};

use crate::error::Result;
use crate::kb_jwt::KbJwt;
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::vc::core::HolderBinder;

use crate::keys::FixtureKey;

/// Builder for a `vp_token` value.
pub struct VpToken<'a> {
    presentation: KbJwt<'a>,
    credential_id: Option<String>,
}

impl<'a> VpToken<'a> {
    /// Starts a `vp_token` presenting `credential`, held by `holder` in `kms`.
    #[must_use]
    pub fn builder(
        kms: &'a LocalKms,
        holder: &'a FixtureKey,
        credential: impl Into<String>,
    ) -> Self {
        Self {
            presentation: KbJwt::builder(kms, holder, credential),
            credential_id: Some("fixture-credential".to_string()),
        }
    }

    /// Sets the nonce the presentation binds to.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.presentation = self.presentation.nonce(nonce);
        self
    }

    /// Sets the verifier the presentation is addressed to.
    #[must_use]
    pub fn verifier_id(mut self, verifier_id: impl Into<String>) -> Self {
        self.presentation = self.presentation.verifier_id(verifier_id);
        self
    }

    /// Keys the presentation under `credential_id`, the DCQL response shape.
    #[must_use]
    pub fn credential_id(mut self, credential_id: impl Into<String>) -> Self {
        self.credential_id = Some(credential_id.into());
        self
    }

    /// Emits a bare presentation string instead of a DCQL-keyed map.
    #[must_use]
    pub fn bare(mut self) -> Self {
        self.credential_id = None;
        self
    }

    /// The holder binding the presentation is built against.
    #[must_use]
    pub fn holder_binder(&self) -> HolderBinder {
        self.presentation.holder_binder()
    }

    /// Builds the presentation and wraps it as a `vp_token` value.
    ///
    /// # Errors
    ///
    /// See [`crate::kb_jwt::KbJwt::build`].
    pub async fn build(self) -> Result<Value> {
        let credential_id = self.credential_id.clone();
        let vp = self.presentation.build().await?;

        Ok(match credential_id {
            Some(id) => {
                let mut map = Map::new();
                map.insert(id, Value::Array(vec![Value::from(vp)]));
                Value::Object(map)
            }
            None => Value::from(vp),
        })
    }
}
