use crate::did::resolver::{DIDResolver, JsDIDResolver};
use crate::http::ReqwestHttpClient;
use crate::kms::{JsKeyHandle, JsKms, Kms};
use crate::nonce::{JsNonceHandler, NonceHandler};
use crate::utils;
use crate::vault::{JsVault, Vault};
use crate::vc::oid4vp::WalletMetadata;
use crate::vc::oid4vp::holder::OID4VPHolder;
use agent_sdk::vc::oid4vp::HolderBuilder;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// A builder for creating an `OID4VP` `Holder` API instance.
#[wasm_bindgen]
pub struct OID4VPHolderBuilder(
    HolderBuilder<JsKeyHandle, JsKms, JsVault, agent_sdk::reqwest::ReqwestClient>,
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
    pub fn new(kms: Kms, vault: Vault, client_id: String, http_client: &ReqwestHttpClient) -> Self {
        let builder = HolderBuilder::new(
            JsKms::new(kms),
            JsVault::new(vault),
            client_id,
            http_client.inner(),
        );
        OID4VPHolderBuilder(builder)
    }

    /// Sets custom did resolver for the holder.
    ///
    /// This method allows providing a custom did resolver.
    /// If provided, it can be used to resolve did into the did document
    ///
    /// # Arguments
    ///
    /// * `did_resolver` - did resolver implementing `DIDResolver`.
    #[wasm_bindgen(js_name = withDidResolver)]
    pub fn with_did_resolver(self, did_resolver: DIDResolver) -> Result<Self, JsError> {
        self.0
            .with_did_resolver(JsDIDResolver::new(did_resolver))
            .map(OID4VPHolderBuilder)
            .map_err(JsError::from)
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

    /// Sets custom nonce_handler for the holder.
    ///
    /// This NonceHandler is used to generate 'wallet_nonce' and to validate it
    /// during fetching AuthorizationRequest via reference.
    /// Details can be found here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#name-request-uri-method-post
    /// If not provided, wallet nonce is not handled
    ///
    /// # Arguments
    ///
    /// * `nonce_handler` - in implementation of NonceHandler trait.
    #[wasm_bindgen(js_name = withNonceHandler)]
    pub fn with_nonce_handler(self, nonce_handler: NonceHandler) -> Self {
        OID4VPHolderBuilder(
            self.0
                .with_nonce_handler(Box::new(JsNonceHandler::new(nonce_handler))),
        )
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
