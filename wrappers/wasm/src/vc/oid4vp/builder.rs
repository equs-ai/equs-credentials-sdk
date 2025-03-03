use crate::http::HttpClient;
use crate::inmem::kms::InMemKms;
use crate::inmem::vault::InMemVault;
use crate::utils;
use crate::vc::oid4vp::holder::OID4VPHolder;
use crate::vc::oid4vp::WalletMetadata;
use agent_sdk::vc::oid4vp::HolderBuilder;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

/// A builder for creating an `OID4VP` `Holder` API instance.
#[wasm_bindgen]
pub struct OID4VPHolderBuilder(
    HolderBuilder<
        agent_sdk::inmem::kms::KeyHandle,
        agent_sdk::inmem::kms::LocalKms,
        agent_sdk::inmem::vault::InMemVault,
        agent_sdk::reqwest::ReqwestClient,
    >,
);

#[wasm_bindgen]
impl OID4VPHolderBuilder {
    /// Creates a new instance of `HolderBuilder` with default configurations.
    ///
    /// # Arguments
    ///
    /// * `kms` - a Key Management System (KMS) instance responsible for managing cryptographic keys.
    /// * `vault` - a Vault service used for securely storing credentials.
    /// * `client_id` - the Client ID of the `Holder`.
    #[wasm_bindgen(constructor)]
    pub fn new(kms: &InMemKms, vault: &InMemVault, client_id: String) -> Self {
        OID4VPHolderBuilder(HolderBuilder::new(kms.inner(), vault.inner(), client_id))
    }

    /// Sets a custom HTTP client for the holder.
    ///
    /// This method allows providing a custom HTTP client for the holder.
    /// If not provided, a default HTTP client will be used.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a custom HTTP client instance.
    #[wasm_bindgen(js_name = withHttpClient)]
    pub fn with_http_client(self, client: &HttpClient) -> Self {
        OID4VPHolderBuilder(self.0.with_http_client(client.inner()))
    }

    /// Sets custom wallet metadata for the holder.
    ///
    /// This method allows providing a custom wallet metadata.
    /// If not provided, a default will be used.
    ///
    /// # Arguments
    ///
    /// * `wallet_metadata` - metadata defining the credential formats, proof types, and algorithms supported by the wallet.
    #[wasm_bindgen(js_name = withWalletMetadata)]
    pub fn with_wallet_metadata(self, wallet_metadata: WalletMetadata) -> Result<Self, JsError> {
        let wallet_metadata = utils::convert_to_rust_object(wallet_metadata)?;

        Ok(OID4VPHolderBuilder(
            self.0.with_wallet_metadata(wallet_metadata),
        ))
    }

    /// Builds the `Holder` API instance based on the current configuration of the builder.
    ///
    /// # Returns
    ///
    /// The `Holder` API instance on success.
    ///
    /// # Errors
    ///
    /// Returns and error if the build process fails.
    pub async fn build(self) -> Result<OID4VPHolder, JsError> {
        let holder = self
            .0
            .build()
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        Ok(OID4VPHolder::from_holder(holder))
    }
}
