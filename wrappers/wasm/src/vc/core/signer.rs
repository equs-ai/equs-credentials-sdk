use crate::did::universal_resolver::UniversalDIDResolver;
use crate::kms::{JsKms, Kms};
use crate::utils::{convert_to_opaque_object_unchecked, convert_to_rust_object};
use crate::vc::{Credential, JsCredential};
use equs_sdk::vc::core::{
    CredentialSigner as CoreCredentialSigner, SignCredential, UnsignedCredential,
};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// An async low-level `SignCredential` API.
///
/// Carries only what the signing step needs — a {@link Kms} for key access and a
/// DID resolver for LDP proof assembly. Use when the prepare/sign split is
/// driven from application code and a full issuer service is not desired.
#[wasm_bindgen(js_name = "VCCoreCredentialSigner")]
pub struct VcCoreCredentialSigner(Box<dyn SignCredential>);

#[wasm_bindgen(js_class = "VCCoreCredentialSigner")]
impl VcCoreCredentialSigner {
    /// Create a new credential signer.
    #[wasm_bindgen(constructor)]
    pub fn new(kms: Kms, did_resolver: &UniversalDIDResolver) -> Self {
        let signer = CoreCredentialSigner::new(JsKms::new(kms), did_resolver.inner());
        Self(Box::new(signer))
    }

    /// Sign an unsigned credential and return the finished {@link Credential}.
    ///
    /// The `unsigned` argument is the externally-tagged JSON shape of the SDK's
    /// `UnsignedCredential` enum — `{ "SdJwt": { ... } }` or
    /// `{ "Ldp": { ... } }`.
    #[wasm_bindgen(js_name = signCredential)]
    pub async fn sign_credential(
        &self,
        unsigned: super::WasmUnsignedCredential,
    ) -> Result<Credential, JsError> {
        let unsigned: UnsignedCredential = convert_to_rust_object(unsigned)?;
        let credential = self
            .0
            .sign_credential(unsigned)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        let js_credential: JsCredential = credential.try_into()?;
        convert_to_opaque_object_unchecked(js_credential)
    }
}
