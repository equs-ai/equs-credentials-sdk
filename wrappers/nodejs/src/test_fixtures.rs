//! `FixtureGenerator`: `equs-test-fixtures`' `Generator` for the TypeScript
//! suites. Built only with the `test-fixtures` feature.

use napi::{Error, Result};
use napi_derive::napi;
use serde_json::Value;
use test_fixtures::generator::Generator;

fn to_napi(err: test_fixtures::Error) -> Error {
    Error::from_reason(err.to_string())
}

#[napi(object, js_name = "FixturePresentation")]
pub struct JsFixturePresentation {
    pub credential: String,
    pub presentation: String,
}

#[napi(object, js_name = "FixtureStatusPair")]
pub struct JsFixtureStatusPair {
    pub status_list_jwt: String,
    pub credential: String,
}

#[napi]
pub struct FixtureGenerator(Generator);

#[napi]
impl FixtureGenerator {
    #[napi]
    pub async fn create() -> Result<FixtureGenerator> {
        Generator::new().await.map(Self).map_err(to_napi)
    }

    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.0.issuer_did().to_string()
    }

    #[napi(getter)]
    pub fn holder_did(&self) -> String {
        self.0.holder_did().to_string()
    }

    #[napi(getter)]
    pub fn verifier_kid(&self) -> String {
        self.0.verifier_kid().to_string()
    }

    #[napi]
    pub async fn sd_jwt_vc(&self) -> Result<String> {
        self.0.sd_jwt_vc().await.map_err(to_napi)
    }

    #[napi]
    pub async fn presentation(&self) -> Result<JsFixturePresentation> {
        let p = self.0.presentation().await.map_err(to_napi)?;
        Ok(JsFixturePresentation {
            credential: p.credential,
            presentation: p.presentation,
        })
    }

    #[napi]
    pub async fn status_pair(&self, url: String) -> Result<JsFixtureStatusPair> {
        let p = self.0.status_pair(&url).await.map_err(to_napi)?;
        Ok(JsFixtureStatusPair {
            status_list_jwt: p.status_list_jwt,
            credential: p.credential,
        })
    }

    #[napi]
    pub async fn access_token(&self) -> Result<String> {
        self.0.access_token().await.map_err(to_napi)
    }

    #[napi]
    pub async fn proof_jwt(&self) -> Result<String> {
        self.0.proof_jwt().await.map_err(to_napi)
    }

    #[napi]
    pub async fn auth_response_jwe(&self, payload: Value) -> Result<String> {
        self.0.auth_response_jwe(payload).await.map_err(to_napi)
    }
}
