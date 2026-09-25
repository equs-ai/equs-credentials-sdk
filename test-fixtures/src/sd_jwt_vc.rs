//! Issuer-signed SD-JWT VC.
//!
//! Built through the SDK's own `VCFormatsSdJwtAPI::create_vc`, so the
//! disclosure machinery, the `cnf` binding and the `dc+sd-jwt` header are the
//! production ones rather than a fixture's guess at them.

use equs_sdk::Duration;
use equs_sdk::vc::claims::Claims;
use equs_sdk::vc::{VCFormatsAPI, VCFormatsSdJwtAPI, VCMetadata};
use serde_json::{Map, Value};

use crate::claims::{DEFAULT_VCT, from_now};
use crate::error::{Error, Result};
use crate::keys::FixtureKey;

/// Builder for an issuer-signed SD-JWT VC.
///
/// The issuer key signs; the holder key is bound into `cnf`. Both are required,
/// because an SD-JWT VC with neither is not a credential.
pub struct SdJwtVc<'a> {
    issuer: &'a FixtureKey,
    holder: &'a FixtureKey,
    vct: String,
    lifetime: Option<Duration>,
    disclosures: Vec<String>,
    claims: Map<String, Value>,
}

impl<'a> SdJwtVc<'a> {
    /// Starts a credential issued by `issuer` and bound to `holder`.
    #[must_use]
    pub fn builder(issuer: &'a FixtureKey, holder: &'a FixtureKey) -> Self {
        let mut claims = Map::new();
        claims.insert("name".to_string(), Value::from("John"));
        claims.insert("surname".to_string(), Value::from("Doe"));

        Self {
            issuer,
            holder,
            vct: DEFAULT_VCT.to_string(),
            lifetime: Some(Duration::days(365)),
            disclosures: vec!["$.name".to_string(), "$.surname".to_string()],
            claims,
        }
    }

    /// Sets the credential type (`vct`).
    #[must_use]
    pub fn vct(mut self, vct: impl Into<String>) -> Self {
        self.vct = vct.into();
        self
    }

    /// Sets how far in the future `exp` lands.
    ///
    /// `create_vc` omits `exp` when this is `None` and no `exp` claim is set;
    /// the delegation and presentation paths both want one, so it defaults to a
    /// year.
    #[must_use]
    pub fn lifetime(mut self, lifetime: Option<Duration>) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Expires the credential, by writing an `exp` in the past.
    #[must_use]
    pub fn expired(mut self) -> Self {
        self.claims
            .insert("exp".to_string(), Value::from(from_now(Duration::days(-1))));
        self
    }

    /// Replaces the selectively disclosable claim paths (`$.name` form).
    #[must_use]
    pub fn disclosures(mut self, disclosures: Vec<String>) -> Self {
        self.disclosures = disclosures;
        self
    }

    /// Overrides or adds a raw claim.
    #[must_use]
    pub fn claim(mut self, name: impl Into<String>, value: Value) -> Self {
        self.claims.insert(name.into(), value);
        self
    }

    /// Replaces the whole claim set.
    #[must_use]
    pub fn claims(mut self, claims: Map<String, Value>) -> Self {
        self.claims = claims;
        self
    }

    /// Issues the credential and returns the compact SD-JWT.
    ///
    /// # Errors
    ///
    /// * [`Error::Json`] — the claim set is not a valid [`Claims`] map.
    /// * [`Error::Sdk`] — `create_vc` rejected the input or the signature failed.
    pub async fn build(self) -> Result<String> {
        let claims: Claims =
            Value::Object(self.claims)
                .try_into()
                .map_err(|e: equs_sdk::vc::claims::Error| Error::Json {
                    details: e.to_string(),
                })?;

        VCFormatsSdJwtAPI::create_vc(
            claims,
            (&self.issuer.did_url, self.issuer.handle.clone()),
            (&self.holder.did_url, self.holder.handle.clone()),
            VCMetadata {
                vct: self.vct,
                lifetime: self.lifetime,
                disclosures: self.disclosures,
                credential_status: None,
            },
            equs_sdk::did::universal::UniversalResolver::default(),
        )
        .await
        .map_err(|e| Error::Sdk {
            details: e.to_string(),
        })
    }
}
