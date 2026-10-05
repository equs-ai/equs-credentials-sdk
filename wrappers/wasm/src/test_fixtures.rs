//! `FixtureGenerator`: `equs-test-fixtures`' `Generator` for the TypeScript
//! suites. Built only with the `test-utils` feature.

use test_fixtures::generator::Generator;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

fn to_js(err: test_fixtures::Error) -> JsError {
    JsError::new(&err.to_string())
}

#[wasm_bindgen(getter_with_clone)]
pub struct FixturePresentation {
    pub credential: String,
    pub presentation: String,
}

#[wasm_bindgen(getter_with_clone)]
pub struct FixtureStatusPair {
    #[wasm_bindgen(js_name = statusListJwt)]
    pub status_list_jwt: String,
    pub credential: String,
}

#[wasm_bindgen]
pub struct FixtureGenerator(Generator);

#[wasm_bindgen]
impl FixtureGenerator {
    pub async fn create() -> Result<FixtureGenerator, JsError> {
        Generator::new().await.map(Self).map_err(to_js)
    }

    #[wasm_bindgen(getter, js_name = issuerDid)]
    pub fn issuer_did(&self) -> String {
        self.0.issuer_did().to_string()
    }

    #[wasm_bindgen(getter, js_name = holderDid)]
    pub fn holder_did(&self) -> String {
        self.0.holder_did().to_string()
    }

    #[wasm_bindgen(getter, js_name = verifierKid)]
    pub fn verifier_kid(&self) -> String {
        self.0.verifier_kid().to_string()
    }

    #[wasm_bindgen(js_name = sdJwtVc)]
    pub async fn sd_jwt_vc(&self) -> Result<String, JsError> {
        self.0.sd_jwt_vc().await.map_err(to_js)
    }

    pub async fn presentation(&self) -> Result<FixturePresentation, JsError> {
        let p = self.0.presentation().await.map_err(to_js)?;
        Ok(FixturePresentation {
            credential: p.credential,
            presentation: p.presentation,
        })
    }

    #[wasm_bindgen(js_name = statusPair)]
    pub async fn status_pair(&self, url: String) -> Result<FixtureStatusPair, JsError> {
        let p = self.0.status_pair(&url).await.map_err(to_js)?;
        Ok(FixtureStatusPair {
            status_list_jwt: p.status_list_jwt,
            credential: p.credential,
        })
    }

    #[wasm_bindgen(js_name = accessToken)]
    pub async fn access_token(&self) -> Result<String, JsError> {
        self.0.access_token().await.map_err(to_js)
    }

    #[wasm_bindgen(js_name = proofJwt)]
    pub async fn proof_jwt(&self) -> Result<String, JsError> {
        self.0.proof_jwt().await.map_err(to_js)
    }

    #[wasm_bindgen(js_name = authResponseJwe)]
    pub async fn auth_response_jwe(&self, payload: JsValue) -> Result<String, JsError> {
        let payload = serde_wasm_bindgen::from_value(payload).map_err(JsError::from)?;
        self.0.auth_response_jwe(payload).await.map_err(to_js)
    }
}
