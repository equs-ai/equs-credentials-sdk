use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "NonceData")]
    pub type NonceData;

    #[wasm_bindgen(typescript_type = "KeyMetadata")]
    pub type KeyMetadata;

    #[wasm_bindgen(typescript_type = "KeyType")]
    pub type KeyType;

    #[wasm_bindgen(typescript_type = "Alg")]
    pub type Alg;
}
