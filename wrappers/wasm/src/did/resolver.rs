use crate::did::{DIDResolution, ResolutionOptions};
use crate::utils;
use async_trait::async_trait;
use equs_sdk::did::{ResolutionError, ResolutionOutput, SpruceDID};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {

    #[wasm_bindgen(typescript_type = "DIDResolver")]
    pub type DIDResolver;

    #[wasm_bindgen(structural, method, catch, js_name = resolveRepresentation)]
    pub async fn resolve_representation(
        this: &DIDResolver,
        did: String,
        options: ResolutionOptions,
    ) -> Result<DIDResolution, JsValue>;

    #[wasm_bindgen(structural, method, getter, js_name = methodName)]
    pub fn method_name(this: &DIDResolver) -> String;
}

pub(crate) struct JsDIDResolver(DIDResolver);

impl JsDIDResolver {
    pub fn new(resolver: DIDResolver) -> Self {
        Self(resolver)
    }
}

#[async_trait(?Send)]
impl equs_sdk::did::universal::DIDResolver for JsDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a SpruceDID,
        options: equs_sdk::did::ResolutionOptions,
    ) -> Result<ResolutionOutput, ResolutionError> {
        let options = utils::convert_to_opaque_object_unchecked(options).map_err(|e| {
            ResolutionError::Internal(format!("Could not convert ResolutionOptions: {:?}", e))
        })?;

        let did_resolution_result = self
            .0
            .resolve_representation(did.as_str().to_owned(), options)
            .await
            .map_err(|e| ResolutionError::Internal(utils::js_value_to_string(e)))?;

        did_resolution_result
            .try_into()
            .map_err(|e| ResolutionError::Internal(format!("{:?}", e)))
    }

    fn method_name(&self) -> String {
        self.0.method_name()
    }
}
