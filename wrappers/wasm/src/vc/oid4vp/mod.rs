use wasm_bindgen::prelude::wasm_bindgen;

mod builder;
mod holder;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ClientMetadata")]
    pub type ClientMetadata;

    #[wasm_bindgen(typescript_type = "PresentationDefinition")]
    pub type PresentationDefinition;
    #[wasm_bindgen(typescript_type = "AuthorizationResponseMetadata")]
    pub type AuthorizationResponseMetadata;

    #[wasm_bindgen(typescript_type = "CommonAuthorizationRequest")]
    pub type RustAuthorizationRequest;
    #[wasm_bindgen(typescript_type = "CredentialMapping")]
    pub type CredentialMapping;

    #[wasm_bindgen(typescript_type = "CredentialsMapping")]
    pub type CredentialsMapping;

    #[wasm_bindgen(typescript_type = "WalletMetadata")]
    pub type WalletMetadata;

    #[wasm_bindgen(typescript_type = "AuthorizationRequest")]
    pub type AuthorizationRequest;

    #[wasm_bindgen(typescript_type = "PresentationResult")]
    pub type PresentationResult;

    #[wasm_bindgen(method)]
    fn getAuthRequest(this: &AuthorizationRequest) -> RustAuthorizationRequest;

    #[wasm_bindgen(constructor)]
    fn new(params: &RustAuthorizationRequest) -> AuthorizationRequest;
}
