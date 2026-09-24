//! OID4VCI proof-of-possession JWT (`typ: openid4vci-proof+jwt`).
//!
//! The SDK's own generator lives in `vc::pop::jwt_pop`, a private module, so the
//! claim set is assembled here and signed through the key's KMS handle. The
//! SDK's verifier is private too, which is why the round-trip check for this
//! kind lives in the SDK's own unit tests (`src/vc/pop/jwt_pop.rs`) rather than
//! in this crate's suite.

use serde_json::{Map, Value};

use crate::claims::{DEFAULT_AUDIENCE, DEFAULT_LIFETIME, from_now, now};
use crate::error::Result;
use crate::jws::{merge, sign_compact};
use crate::keys::FixtureKey;
use equs_sdk::Duration;

/// The `typ` header OID4VCI requires on a proof-of-possession JWT.
pub const POP_TYP: &str = "openid4vci-proof+jwt";

/// Builder for a proof-of-possession JWT.
///
/// `aud` and `exp` are the claims OID4VCI requires; both default and both are
/// overridable. `iss`, `nbf` and `nonce` are omitted unless set.
pub struct ProofOfPossession<'a> {
    key: &'a FixtureKey,
    audience: String,
    lifetime: Duration,
    issuer: Option<String>,
    not_before: Option<i64>,
    nonce: Option<String>,
    overrides: Map<String, Value>,
}

impl<'a> ProofOfPossession<'a> {
    /// Starts a proof-of-possession bound to `key`.
    #[must_use]
    pub fn builder(key: &'a FixtureKey) -> Self {
        Self {
            key,
            audience: DEFAULT_AUDIENCE.to_string(),
            lifetime: DEFAULT_LIFETIME,
            issuer: None,
            not_before: None,
            nonce: None,
            overrides: Map::new(),
        }
    }

    /// Sets `aud`. The issuer checks this against its own identifier.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Sets how far in the future `exp` lands. A negative duration expires it.
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Sets `iss`. Omitted when unset, which is what the SDK's issuer expects.
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets `nbf` as a Unix timestamp.
    #[must_use]
    pub fn not_before(mut self, not_before: i64) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Sets `nonce`, the value the issuer's nonce handler will compare.
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Overrides or adds a raw claim, applied after every default.
    #[must_use]
    pub fn claim(mut self, name: impl Into<String>, value: Value) -> Self {
        self.overrides.insert(name.into(), value);
        self
    }

    /// Signs the proof and returns the compact JWT.
    ///
    /// # Errors
    ///
    /// See [`crate::jws::sign_compact`].
    pub async fn build(self) -> Result<String> {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), Value::from(self.audience));
        claims.insert("iat".to_string(), Value::from(now()));
        claims.insert("exp".to_string(), Value::from(from_now(self.lifetime)));
        if let Some(issuer) = self.issuer {
            claims.insert("iss".to_string(), Value::from(issuer));
        }
        if let Some(not_before) = self.not_before {
            claims.insert("nbf".to_string(), Value::from(not_before));
        }
        if let Some(nonce) = self.nonce {
            claims.insert("nonce".to_string(), Value::from(nonce));
        }
        merge(&mut claims, self.overrides);

        sign_compact(self.key, POP_TYP, &Value::Object(claims)).await
    }
}
