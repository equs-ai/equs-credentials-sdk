use crate::vc::core::JsCredential;
use agent_sdk::vault::CredentialEntry;
use napi_derive::napi;

mod js;
mod native;
#[cfg(debug_assertions)]
pub mod test;
mod unified;

pub use js::JsVault;
pub use native::NativeVault;
pub use unified::UnifiedVault;

#[napi(js_name = "CredentialEntry", object)]
pub struct JsCredentialEntry {
    pub credential: JsCredential,
    pub kid: String,
    pub id: String,
}

impl TryFrom<CredentialEntry> for JsCredentialEntry {
    type Error = napi::Error;

    fn try_from(value: CredentialEntry) -> napi::Result<Self> {
        Ok(JsCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

impl TryFrom<JsCredentialEntry> for CredentialEntry {
    type Error = napi::Error;

    fn try_from(value: JsCredentialEntry) -> napi::Result<Self> {
        Ok(CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}
