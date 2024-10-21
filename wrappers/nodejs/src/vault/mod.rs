use agent_sdk::vault::{CredentialEntry, FindCriteria};
use napi::bindgen_prelude::Object;
use napi::Env;
use napi_derive::napi;

use crate::vc::core::JsCredential;

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
}

impl TryFrom<CredentialEntry> for JsCredentialEntry {
    type Error = napi::Error;

    fn try_from(value: CredentialEntry) -> napi::Result<Self> {
        Ok(JsCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
        })
    }
}

impl TryFrom<JsCredentialEntry> for CredentialEntry {
    type Error = napi::Error;

    fn try_from(value: JsCredentialEntry) -> napi::Result<Self> {
        Ok(CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
        })
    }
}

#[napi]
pub struct CredentialSearchCriteria(FindCriteria);

#[napi]
impl CredentialSearchCriteria {
    #[napi(factory)]
    pub fn by_type_and_format(type_: String, format: String) -> Self {
        CredentialSearchCriteria(FindCriteria::ByTypeAndFormat(type_, format))
    }

    #[napi(
        js_name = "value",
        ts_return_type = "Promise<{type: 'ByTypeAndFormat', cred_type: string, format: string} | {type: 'Other'}>"
    )]
    pub fn js_value(&self, env: Env) -> napi::Result<Object> {
        let mut obj = env.create_object()?;

        match &self.0 {
            FindCriteria::ByTypeAndFormat(type_, format) => {
                obj.set("type", "ByTypeAndFormat")?;
                obj.set("cred_type", type_)?;
                obj.set("format", format)?;
            }
            _ => obj.set("type", "Other")?,
        }

        Ok(obj)
    }
}
