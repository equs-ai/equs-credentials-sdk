use crate::did::JsUniversalDIDResolver;
use crate::error::IntoNapiError;
use crate::kms::JsKms;
use crate::utils::from_json_object;
use crate::vc::JsonObject;
use crate::vc::core::JsCredential;
use equs_sdk::vc::core::{
    CredentialSigner as CoreCredentialSigner, SignCredential, UnsignedCredential,
};
use napi::Error;
use napi_derive::napi;

/// An async low-level `SignCredential` API.
///
/// Carries only what the signing step needs — a {@link Kms} for key access and a
/// DID resolver for LDP proof assembly. Use when the `Prepare`/`Sign` split is
/// driven from application code (e.g. a remote signing service or HSM-backed
/// adapter) and a full {@link VCCoreIssuer} is not desired.
///
/// @property signCredential - {@link VCCoreCredentialSigner.signCredential}
#[napi(js_name = "_VCCoreCredentialSigner")]
pub struct JsVCCoreCredentialSigner(pub(crate) Box<dyn SignCredential>);

#[napi]
impl JsVCCoreCredentialSigner {
    /// Create a new credential signer.
    #[napi(constructor)]
    pub fn new(kms: JsKms, did_resolver: &JsUniversalDIDResolver) -> Self {
        let signer = CoreCredentialSigner::new(kms, did_resolver.into());
        JsVCCoreCredentialSigner(Box::new(signer))
    }

    /// Sign an unsigned credential and return the finished {@link Credential}.
    ///
    /// The `unsigned` argument is the externally-tagged JSON serialisation of the
    /// SDK's `UnsignedCredential` enum — `{ "SdJwt": { ... } }` or
    /// `{ "Ldp": { ... } }`.
    ///
    /// @param unsigned - serialised {@link UnsignedCredential}
    /// @returns {Credential} - the signed credential on success
    #[napi]
    pub async fn sign_credential(
        &self,
        #[napi(ts_arg_type = "UnsignedCredential")] unsigned: JsonObject,
    ) -> Result<JsCredential, Error> {
        let unsigned: UnsignedCredential = from_json_object(unsigned)?;
        self.0
            .sign_credential(unsigned)
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(|v| v.try_into())
    }
}
