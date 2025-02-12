use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use js_sys::Promise;
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use std::rc::Rc;
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen(typescript_custom_section)]
const TS_IMPORT: &'static str = include_str!("../../../nodejs/index.ts");

#[wasm_bindgen]
pub struct NativeDIDResolver(Rc<UniversalResolver>);

#[wasm_bindgen]
impl NativeDIDResolver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> NativeDIDResolver {
        let resolver = UniversalResolver::default();

        NativeDIDResolver(Rc::new(resolver))
    }

    #[wasm_bindgen(unchecked_return_type = "DIDVerificationMethod")]
    pub async fn resolve_verification_method(&self, did: String) -> Promise {
        let resolver = self.0.clone();
        future_to_promise(async move {
            let vm = resolver
                .resolve_into_any_verification_method(
                    &DIDBuf::from_str(&did).map_err(JsError::from)?,
                )
                .await
                .map_err(JsError::from)?;

            let ser = Serializer::json_compatible();
            let res = vm.serialize(&ser).map_err(JsError::from)?;

            Ok(res)
        })
    }

    #[wasm_bindgen(unchecked_return_type = "DIDResolution")]
    pub async fn resolve(&self, did: String) -> Promise {
        let resolver = self.0.clone();
        future_to_promise(async move {
            let output = resolver
                .resolve(&DIDBuf::from_str(&did).map_err(JsError::from)?)
                .await
                .map_err(JsError::from)
                .map(|output| {
                    serde_json::json!({
                        "document": output.document,
                        "metadata": output.metadata,
                        "document_metadata": output.document_metadata,
                    })
                })?;

            let ser = Serializer::json_compatible();
            let res = output.serialize(&ser).map_err(JsError::from)?;

            Ok(res)
        })
    }
}
