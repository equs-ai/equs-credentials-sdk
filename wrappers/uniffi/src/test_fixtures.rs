//! `FixtureGenerator`: `equs-test-fixtures`' `Generator` for the Kotlin and
//! Swift suites. Built only with the `test-fixtures` feature.

use crate::common::{Error, Result};
use std::sync::Arc;
use test_fixtures::generator::Generator;

fn to_uniffi(err: test_fixtures::Error) -> Error {
    Error::Core(err.to_string())
}

#[derive(uniffi::Record)]
pub struct FixturePresentation {
    pub credential: String,
    pub presentation: String,
}

#[derive(uniffi::Record)]
pub struct FixtureStatusPair {
    pub status_list_jwt: String,
    pub credential: String,
}

#[derive(uniffi::Object)]
pub struct FixtureGenerator(Generator);

#[uniffi::export(async_runtime = "tokio")]
pub async fn create_fixture_generator() -> Result<Arc<FixtureGenerator>> {
    Generator::new()
        .await
        .map(|g| Arc::new(FixtureGenerator(g)))
        .map_err(to_uniffi)
}

#[uniffi::export(async_runtime = "tokio")]
impl FixtureGenerator {
    fn issuer_did(&self) -> String {
        self.0.issuer_did().to_string()
    }

    fn holder_did(&self) -> String {
        self.0.holder_did().to_string()
    }

    fn verifier_kid(&self) -> String {
        self.0.verifier_kid().to_string()
    }

    async fn sd_jwt_vc(&self) -> Result<String> {
        self.0.sd_jwt_vc().await.map_err(to_uniffi)
    }

    async fn presentation(&self) -> Result<FixturePresentation> {
        let p = self.0.presentation().await.map_err(to_uniffi)?;
        Ok(FixturePresentation {
            credential: p.credential,
            presentation: p.presentation,
        })
    }

    async fn status_pair(&self, url: String) -> Result<FixtureStatusPair> {
        let p = self.0.status_pair(&url).await.map_err(to_uniffi)?;
        Ok(FixtureStatusPair {
            status_list_jwt: p.status_list_jwt,
            credential: p.credential,
        })
    }

    async fn access_token(&self) -> Result<String> {
        self.0.access_token().await.map_err(to_uniffi)
    }

    async fn proof_jwt(&self) -> Result<String> {
        self.0.proof_jwt().await.map_err(to_uniffi)
    }

    /// `payload` is a JSON document.
    async fn auth_response_jwe(&self, payload: String) -> Result<String> {
        let payload = serde_json::from_str(&payload).map_err(|e| Error::Parse(e.to_string()))?;
        self.0.auth_response_jwe(payload).await.map_err(to_uniffi)
    }
}
