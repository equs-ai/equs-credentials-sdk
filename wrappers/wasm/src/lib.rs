use wasm_bindgen::prelude::wasm_bindgen;

pub mod did;
mod http;
pub mod inmem;
mod utils;
pub mod vc;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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
