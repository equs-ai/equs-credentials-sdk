//! In-process fixture generation for callers that cannot use the builders
//! directly — the wrapper bindings, which hand these values to TypeScript,
//! Kotlin and Swift tests.
//!
//! A [`Generator`] owns one [`LocalKms`] and the issuer, holder and verifier
//! keys, so every fixture it mints is coherent with the others: a presentation
//! is bound to the holder its credential names, a status list is signed by the
//! issuer of the credential that points at it, and a JWE is addressed to the
//! verifier key.

use equs_sdk::inmem::kms::LocalKms;
use serde_json::{Value, json};

use crate::access_token::AccessToken;
use crate::claims::{DEFAULT_ISSUER, DEFAULT_NONCE};
use crate::error::Result;
use crate::jwe::Jwe;
use crate::kb_jwt::KbJwt;
use crate::keys::FixtureKey;
use crate::pop::ProofOfPossession;
use crate::sd_jwt_vc::SdJwtVc;
use crate::status_list::StatusListToken;

/// An SD-JWT VC and a KB-JWT-bound presentation of it.
pub struct Presentation {
    /// The issuer-signed SD-JWT VC.
    pub credential: String,
    /// The SD-JWT VP presenting `credential`.
    pub presentation: String,
}

/// A status list token and an SD-JWT VC whose `status` claim points at index 0
/// of it.
pub struct StatusPair {
    /// The `statuslist+jwt`, with `sub` set to the URL it is served from.
    pub status_list_jwt: String,
    /// The credential referencing that list.
    pub credential: String,
}

/// Mints fixtures on demand from one set of keys.
pub struct Generator {
    kms: LocalKms,
    issuer: FixtureKey,
    holder: FixtureKey,
    verifier: FixtureKey,
}

impl Generator {
    /// Creates the KMS and the issuer, holder and verifier keys.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Kms`], [`crate::Error::Did`] — a key could not be created.
    pub async fn new() -> Result<Self> {
        let kms = LocalKms::new();
        let issuer = FixtureKey::create_default(&kms).await?;
        let holder = FixtureKey::create_default(&kms).await?;
        let verifier = FixtureKey::create_default(&kms).await?;
        Ok(Self {
            kms,
            issuer,
            holder,
            verifier,
        })
    }

    /// The issuer key's DID.
    #[must_use]
    pub fn issuer_did(&self) -> &str {
        &self.issuer.did
    }

    /// The holder key's DID, the `cnf` subject of every credential.
    #[must_use]
    pub fn holder_did(&self) -> &str {
        &self.holder.did
    }

    /// The verifier key's KMS id, the recipient of [`Self::auth_response_jwe`].
    #[must_use]
    pub fn verifier_kid(&self) -> &str {
        &self.verifier.kid
    }

    /// An issuer-signed SD-JWT VC bound to the holder.
    ///
    /// # Errors
    ///
    /// See [`SdJwtVc::build`].
    pub async fn sd_jwt_vc(&self) -> Result<String> {
        SdJwtVc::builder(&self.issuer, &self.holder).build().await
    }

    /// A fresh SD-JWT VC and the holder's presentation of it.
    ///
    /// # Errors
    ///
    /// See [`SdJwtVc::build`] and [`KbJwt::build`].
    pub async fn presentation(&self) -> Result<Presentation> {
        let credential = self.sd_jwt_vc().await?;
        let presentation = KbJwt::builder(&self.kms, &self.holder, credential.clone())
            .build()
            .await?;
        Ok(Presentation {
            credential,
            presentation,
        })
    }

    /// A status list served at `url`, with every entry valid, and a credential
    /// pointing at its index 0.
    ///
    /// # Errors
    ///
    /// See [`StatusListToken::build`] and [`SdJwtVc::build`].
    pub async fn status_pair(&self, url: &str) -> Result<StatusPair> {
        let status_list_jwt = StatusListToken::builder(&self.issuer)
            .url(url)
            .build()
            .await?;
        let credential = SdJwtVc::builder(&self.issuer, &self.holder)
            .claim("status", json!({ "status_list": { "idx": 0, "uri": url } }))
            .build()
            .await?;
        Ok(StatusPair {
            status_list_jwt,
            credential,
        })
    }

    /// An OAuth 2.0 bearer access token signed by the issuer.
    ///
    /// # Errors
    ///
    /// See [`AccessToken::build`].
    pub async fn access_token(&self) -> Result<String> {
        AccessToken::builder(&self.issuer).build().await
    }

    /// An OID4VCI proof-of-possession JWT from the holder, addressed to the
    /// default issuer with the default nonce.
    ///
    /// # Errors
    ///
    /// See [`ProofOfPossession::build`].
    pub async fn proof_jwt(&self) -> Result<String> {
        ProofOfPossession::builder(&self.holder)
            .audience(DEFAULT_ISSUER)
            .nonce(DEFAULT_NONCE)
            .build()
            .await
    }

    /// A compact JWE carrying `payload`, addressed to the verifier key.
    ///
    /// # Errors
    ///
    /// See [`Jwe::build`].
    pub async fn auth_response_jwe(&self, payload: Value) -> Result<String> {
        Jwe::builder(&self.kms, self.verifier.kid.clone())
            .payload(payload)
            .build()
            .await
    }
}
