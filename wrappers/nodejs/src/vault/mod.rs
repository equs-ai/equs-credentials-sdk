use crate::vc::core::JsCredential;
use agent_sdk::vault::{CredentialEntry, CredentialFilter};
use napi::bindgen_prelude::Object;
use napi::Env;
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

#[napi(js_name = "CredentialFilter")]
pub struct JsCredentialFilter(CredentialFilter);

#[napi]
impl JsCredentialFilter {
    #[napi(factory)]
    pub fn by_format(format: String) -> Self {
        JsCredentialFilter(CredentialFilter::Format(format))
    }

    #[napi(factory)]
    pub fn by_tag_keys(fields: Vec<String>) -> Self {
        JsCredentialFilter(CredentialFilter::TagKeys(fields))
    }

    #[napi(factory)]
    pub fn by_tags(key: String, value: String) -> Self {
        JsCredentialFilter(CredentialFilter::Tag(key, value))
    }

    #[napi(
        js_name = "value",
        ts_return_type = "Promise<\
        {type: 'Format', format: string} \
        | {type: 'TagKeys', fields: string[]} \
        | {type: 'Tag', key: string, value: string} \
        | {type: 'Other'\
        }>"
    )]
    pub fn js_value(&self, env: Env) -> napi::Result<Object> {
        let mut obj = env.create_object()?;

        match &self.0 {
            CredentialFilter::Format(format) => {
                obj.set("type", "Format")?;
                obj.set("format", format)?;
            }
            CredentialFilter::TagKeys(fields) => {
                obj.set("type", "TagKeys")?;
                obj.set("fields", fields)?;
            }
            CredentialFilter::Tag(key, value) => {
                obj.set("type", "Tag")?;
                obj.set("key", key)?;
                obj.set("value", value)?;
            }
            _ => obj.set("type", "Other")?,
        }

        Ok(obj)
    }
}
