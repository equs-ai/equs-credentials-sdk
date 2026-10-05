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
    scope: Option<String>,
    lifetime: Duration,
}

impl<'a> AccessToken<'a> {
    /// Starts a token signed by `key`.
    #[must_use]
    pub fn builder(key: &'a FixtureKey) -> Self {
        Self {
            key,
            issuer: DEFAULT_ISSUER.to_string(),
            scope: Some("SD_JWT_cred".to_string()),
            lifetime: DEFAULT_LIFETIME,
        }
    }

    /// Sets `iss` — the authorization server that minted the token.
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
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

    /// Expires the token — `exp` one day in the past.
    #[must_use]
    pub fn expired(mut self) -> Self {
        self.lifetime = Duration::days(-1);
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
        claims.insert("aud".to_string(), Value::from(DEFAULT_AUDIENCE));
        claims.insert("iat".to_string(), Value::from(now()));
        claims.insert("exp".to_string(), Value::from(from_now(self.lifetime)));
        if let Some(scope) = self.scope {
            claims.insert("scope".to_string(), Value::from(scope));
        }

        sign_compact(self.key, "JWT", &Value::Object(claims)).await
    }

    /// The JWKS document a token validator fetches to verify `key`'s signature.
    ///
    /// The returned JWK's `kid` is set to `key.did_url` — the same value
    /// [`crate::jws::sign_compact`] writes into every token's header — so a
    /// `kid`-based lookup (e.g. the SDK's `ByJwks`) resolves it.
    ///
    /// # Errors
    ///
    /// * [`Error::Signing`] — the handle exposed no public JWK.
    /// * [`Error::Json`] — the JWK could not be serialised.
    pub fn jwks_for(key: &FixtureKey) -> Result<Value> {
        let mut jwk = key.handle.jwk().ok_or_else(|| Error::Signing {
            details: "key handle exposed no public JWK".to_string(),
        })?;
        jwk.key_id = Some(key.did_url.to_string());
        let jwk = serde_json::to_value(jwk).map_err(|e| Error::Json {
            details: e.to_string(),
        })?;
        Ok(serde_json::json!({ "keys": [jwk] }))
    }
}
