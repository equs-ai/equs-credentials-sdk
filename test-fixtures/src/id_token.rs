//! SIOP `id_token` (`typ: JWT`).
//!
//! The SDK builds and validates this inside `vc::oid4vp`, with no public
//! constructor, so the claim set is assembled here and signed through the
//! holder key's KMS handle.
//!
//! What the SDK's validator requires, and what the defaults therefore satisfy:
//! `typ` exactly `JWT`, an `alg`, a resolvable `kid`, `iss == sub == the DID in
//! kid`, an `aud` equal to the verifier's full client id, a matching `nonce`,
//! and an `exp` in the future.

use serde_json::{Map, Value};

use crate::claims::{DEFAULT_AUDIENCE, DEFAULT_LIFETIME, DEFAULT_NONCE, from_now, now};
use crate::error::Result;
use crate::jws::{merge, sign_compact};
use crate::keys::FixtureKey;
use equs_sdk::Duration;

/// The `typ` header the SDK's `id_token` validator requires, exactly.
pub const ID_TOKEN_TYP: &str = "JWT";

/// Builder for a SIOP `id_token`.
pub struct IdToken<'a> {
    key: &'a FixtureKey,
    audience: String,
    nonce: String,
    lifetime: Duration,
    subject: Option<String>,
    issuer: Option<String>,
    overrides: Map<String, Value>,
}

impl<'a> IdToken<'a> {
    /// Starts an `id_token` signed by `key`.
    #[must_use]
    pub fn builder(key: &'a FixtureKey) -> Self {
        Self {
            key,
            audience: DEFAULT_AUDIENCE.to_string(),
            nonce: DEFAULT_NONCE.to_string(),
            lifetime: DEFAULT_LIFETIME,
            subject: None,
            issuer: None,
            overrides: Map::new(),
        }
    }

    /// Sets `aud` — the verifier's full client id.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Sets `nonce`, which must match the presentation session's.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Sets how far in the future `exp` lands. A non-positive duration expires it.
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Overrides `sub`. Defaults to the signing key's DID.
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Overrides `iss`. Defaults to the signing key's DID.
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Overrides or adds a raw claim.
    #[must_use]
    pub fn claim(mut self, name: impl Into<String>, value: Value) -> Self {
        self.overrides.insert(name.into(), value);
        self
    }

    /// Signs the `id_token` and returns the compact JWT.
    ///
    /// # Errors
    ///
    /// See [`crate::jws::sign_compact`].
    pub async fn build(self) -> Result<String> {
        let did = self.key.did.clone();

        let mut claims = Map::new();
        claims.insert(
            "iss".to_string(),
            Value::from(self.issuer.unwrap_or_else(|| did.clone())),
        );
        claims.insert("sub".to_string(), Value::from(self.subject.unwrap_or(did)));
        claims.insert("aud".to_string(), Value::from(self.audience));
        claims.insert("nonce".to_string(), Value::from(self.nonce));
        claims.insert("iat".to_string(), Value::from(now()));
        claims.insert("exp".to_string(), Value::from(from_now(self.lifetime)));
        merge(&mut claims, self.overrides);

        sign_compact(self.key, ID_TOKEN_TYP, &Value::Object(claims)).await
    }
}
