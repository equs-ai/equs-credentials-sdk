//! Builds the flat JSON bundle every wrapper test suite reads.
//!
//! [`build`] drives one [`crate::generator::Generator`] through every fixture
//! the wrapper suites read. The result is a [`Bundle`] — a flat map of fixture name to
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

use crate::error::Result;
use crate::generator::Generator;
use crate::status_list::DEFAULT_STATUS_LIST_URL;

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
/// Drives one [`Generator`] through every fixture a wrapper test suite needs,
/// collecting the results into a [`Bundle`]. See the
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
    let generator = Generator::new().await?;
    let mut bundle = Bundle(Map::new());

    let vp = generator.presentation().await?;
    bundle.insert("vc", Value::from(vp.credential.clone()));
    bundle.insert(
        "vp",
        json!({ "credential": vp.credential, "presentation": vp.presentation.clone() }),
    );

    let status = generator.status_pair(DEFAULT_STATUS_LIST_URL).await?;
    bundle.insert("statusListJwt", Value::from(status.status_list_jwt));
    bundle.insert("vcWithStatus", Value::from(status.credential));

    bundle.insert("accessToken", Value::from(generator.access_token().await?));
    bundle.insert("proofJwt", Value::from(generator.proof_jwt().await?));
    bundle.insert("sdJwtCreds", Value::from(generator.sd_jwt_vc().await?));

    let auth_response_jwe = generator
        .auth_response_jwe(json!({ "vp_token": vp.presentation, "state": "fixture-state" }))
        .await?;
    bundle.insert("authResponseJwe", Value::from(auth_response_jwe));

    Ok(bundle)
}
