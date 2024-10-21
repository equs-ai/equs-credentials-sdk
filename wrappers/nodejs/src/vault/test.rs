use crate::vault::{JsVault, NativeVault};
use napi_derive::napi;

#[napi]
pub fn wrap_js_vault(vault: JsVault) -> NativeVault {
    NativeVault::from(vault)
}
