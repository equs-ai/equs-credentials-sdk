//! OAuth 2.0 bearer access token.
//!
//! The SDK's OID4VCI tests were written against Keycloak-issued RS256 tokens.
//! `LocalKms` has no RSA key type, so this builder signs ES256 and the tests
//! assert on claims rather than on `alg` — nothing in the token path branches
//! on the signature algorithm, it resolves a JWK and verifies with it.

use equs_sdk::Duration;
use equs_sdk::crypto::Key;
use serde_json::{Map, Value};

use crate::claims::{DEFAULT_AUDIENCE, DEFAULT_ISSUER, DEFAULT_LIFETIME, from_now, now};
use crate::error::{Error, Result};
use crate::jws::sign_compact;
use crate::keys::FixtureKey;

/// Builder for a bearer access token (`typ: JWT`).
pub struct AccessToken<'a> {
    key: &'a FixtureKey,
    issuer: String,
    audience: String,
    scope: Option<String>,
    lifetime: Duration,
    claims: Map<String, Value>,
}

impl<'a> AccessToken<'a> {
    /// Starts a token signed by `key`.
    #[must_use]
    pub fn builder(key: &'a FixtureKey) -> Self {
        Self {
            key,
            issuer: DEFAULT_ISSUER.to_string(),
            audience: DEFAULT_AUDIENCE.to_string(),
            scope: Some("SD_JWT_cred".to_string()),
            lifetime: DEFAULT_LIFETIME,
            claims: Map::new(),
        }
    }

    /// Sets `iss` — the authorization server that minted the token.
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Sets `aud`.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Sets `scope`.
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Omits `scope` entirely — the shape the scope-rejection paths take.
    #[must_use]
    pub fn without_scope(mut self) -> Self {
        self.scope = None;
        self
    }

    /// Sets how far in the future `exp` lands.
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Expires the token — `exp` one day in the past.
    #[must_use]
    pub fn expired(mut self) -> Self {
        self.lifetime = Duration::days(-1);
        self
    }

    /// Overrides or adds a raw claim.
    #[must_use]
    pub fn claim(mut self, name: impl Into<String>, value: Value) -> Self {
        self.claims.insert(name.into(), value);
        self
    }

    /// Signs and returns the compact token.
    ///
    /// # Errors
    ///
    /// * [`Error::Json`] — the claim set could not be serialised.
    /// * [`Error::Signing`] — the KMS handle refused to sign.
    pub async fn build(self) -> Result<String> {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), Value::from(self.issuer));
        claims.insert("aud".to_string(), Value::from(self.audience));
        claims.insert("iat".to_string(), Value::from(now()));
        claims.insert("exp".to_string(), Value::from(from_now(self.lifetime)));
        if let Some(scope) = self.scope {
            claims.insert("scope".to_string(), Value::from(scope));
        }
        crate::jws::merge(&mut claims, self.claims);

        sign_compact(self.key, "JWT", &Value::Object(claims)).await
    }

    /// The JWKS document a token validator fetches to verify `key`'s signature.
    ///
    /// # Errors
    ///
    /// * [`Error::Signing`] — the handle exposed no public JWK.
    pub fn jwks_for(key: &FixtureKey) -> Result<Value> {
        let jwk = key.handle.jwk().ok_or_else(|| Error::Signing {
            details: "key handle exposed no public JWK".to_string(),
        })?;
        let jwk = serde_json::to_value(jwk).map_err(|e| Error::Json {
            details: e.to_string(),
        })?;
        Ok(serde_json::json!({ "keys": [jwk] }))
    }
}
