use crate::nonce::JsNonceData;
use agent_sdk::nonce::NonceGenerator;
use napi_derive::napi;
use std::sync::Arc;
use time::Duration;

/// An async generic `NonceGenerator` interface for generating nonce.
///
/// @property generate - {@link NativeNonceGenerator.generate}
/// @property withExpiration - {@link NativeNonceGenerator.withExpiration}
#[derive(Clone)]
#[napi]
pub struct NativeNonceGenerator(Arc<dyn NonceGenerator>);

#[napi]
impl NativeNonceGenerator {
    pub fn from<NG: NonceGenerator + 'static>(nonce_generator: NG) -> NativeNonceGenerator {
        NativeNonceGenerator(Arc::new(nonce_generator))
    }

    pub fn inner(&self) -> &dyn NonceGenerator {
        self.0.as_ref()
    }

    /// Generates a `Nonce`.
    ///
    /// @returns {string} - `Nonce` on success
    #[napi]
    pub async fn generate(&self) -> napi::Result<String> {
        self.0
            .generate()
            .await
            .map(|nonce| nonce.secret().to_string())
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    /// Creates a {@link NonceData} with a provided expiration.
    ///
    /// @param {number} expiration - an active duration of `Nonce`.
    ///
    /// @returns {NonceData} - A {@link NonceData} on success.
    #[napi]
    pub async fn with_expiration(&self, expiration: i64) -> napi::Result<JsNonceData> {
        self.0
            .with_expiration(Duration::seconds(expiration))
            .await
            .map(Into::into)
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}
