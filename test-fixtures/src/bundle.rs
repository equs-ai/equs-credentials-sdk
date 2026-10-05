//! Builds the flat JSON bundle every wrapper test suite reads.
//!
//! [`build`] mints one [`equs_sdk::inmem::kms::LocalKms`], the issuer, holder
//! and verifier keys every builder in this crate needs, then drives each of
//! them once. The result is a [`Bundle`] — a flat map of fixture name to
//! value — written to disk by `bin/fixture_gen.rs` and read back by the
//! TypeScript, Kotlin and Swift test suites.
//!
//! # Contract
//!
//! The following keys are always present in a successfully built bundle.
//! They are camelCase because the TypeScript side reads them without a
//! rename layer, and their names and shapes are a contract with the wrapper
//! suites that consume the generated file — do not rename or reshape one
//! without updating every reader.
//!
//! | Key | Shape |
//! |---|---|
//! | `vc` | string — issuer-signed SD-JWT VC |
//! | `vp` | object `{ "credential", "presentation" }` — `vc` presented as a KB-JWT-bound SD-JWT VP |
//! | `statusListJwt` | string — Token Status List JWT |
//! | `vcWithStatus` | string — an SD-JWT VC whose `status` claim points at `statusListJwt`'s list, index 0 |
//! | `accessToken` | string — OAuth 2.0 bearer access token |
//! | `proofJwt` | string — OID4VCI proof-of-possession JWT |
//! | `sdJwtCreds` | string — issuer-signed SD-JWT VC, OID4VCI credential-response shape |
//! | `authResponseJwe` | string — compact JWE encrypting an OID4VP authorization response |

use serde::Serialize;
use serde_json::{Map, Value, json};

use equs_sdk::inmem::kms::LocalKms;

use crate::access_token::AccessToken;
use crate::claims::{DEFAULT_ISSUER, DEFAULT_NONCE};
use crate::error::Result;
use crate::jwe::Jwe;
use crate::kb_jwt::KbJwt;
use crate::keys::FixtureKey;
use crate::pop::ProofOfPossession;
use crate::sd_jwt_vc::SdJwtVc;
use crate::status_list::{DEFAULT_STATUS_LIST_URL, StatusListToken};

/// The wrapper fixture bundle: a flat map of fixture name to value.
///
/// A value is a token string for most kinds, or — for a kind whose consumer
/// needs both a credential and something bound to it — an object such as
/// `{"credential": …, "presentation": …}`. See the [module docs](self) for
/// the exact keys this crate emits and their shapes.
#[derive(Debug, Serialize)]
pub struct Bundle(Map<String, Value>);

impl Bundle {
    fn insert(&mut self, name: &str, value: Value) {
        self.0.insert(name.to_string(), value);
    }

    /// The value stored under `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    /// How many fixtures the bundle holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the bundle holds no fixtures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Builds the wrapper fixture bundle.
///
/// Mints one [`LocalKms`] and three [`FixtureKey`]s — issuer, holder,
/// verifier — then drives every builder in this crate that a wrapper test
/// suite needs, collecting the results into a [`Bundle`]. See the
/// [module docs](self) for the full key contract.
///
/// # Errors
///
/// * [`crate::Error::Kms`], [`crate::Error::Did`] — a fixture key could not
///   be created.
/// * [`crate::Error::Json`], [`crate::Error::Signing`], [`crate::Error::Sdk`]
///   — one of the builders failed; see that builder's own `build` for the
///   exact cause.
pub async fn build() -> Result<Bundle> {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await?;
    let holder = FixtureKey::create_default(&kms).await?;
    let verifier = FixtureKey::create_default(&kms).await?;

    let mut bundle = Bundle(Map::new());

    let vc = SdJwtVc::builder(&issuer, &holder).build().await?;
    let presentation = KbJwt::builder(&kms, &holder, vc.clone()).build().await?;
    bundle.insert("vc", Value::from(vc.clone()));
    bundle.insert(
        "vp",
        json!({ "credential": vc.clone(), "presentation": presentation.clone() }),
    );

    let status_list_jwt = StatusListToken::builder(&issuer).build().await?;
    bundle.insert("statusListJwt", Value::from(status_list_jwt));

    let vc_with_status = SdJwtVc::builder(&issuer, &holder)
        .claim(
            "status",
            json!({ "status_list": { "idx": 0, "uri": DEFAULT_STATUS_LIST_URL } }),
        )
        .build()
        .await?;
    bundle.insert("vcWithStatus", Value::from(vc_with_status));

    let access_token = AccessToken::builder(&issuer).build().await?;
    bundle.insert("accessToken", Value::from(access_token));

    let proof_jwt = ProofOfPossession::builder(&holder)
        .audience(DEFAULT_ISSUER)
        .nonce(DEFAULT_NONCE)
        .build()
        .await?;
    bundle.insert("proofJwt", Value::from(proof_jwt));

    let sd_jwt_creds = SdJwtVc::builder(&issuer, &holder).build().await?;
    bundle.insert("sdJwtCreds", Value::from(sd_jwt_creds));

    let auth_response_jwe = Jwe::builder(&kms, verifier.kid.clone())
        .payload(json!({ "vp_token": presentation, "state": "fixture-state" }))
        .build()
        .await?;
    bundle.insert("authResponseJwe", Value::from(auth_response_jwe));

    Ok(bundle)
}
