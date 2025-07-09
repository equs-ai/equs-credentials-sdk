use agent_sdk::vc::oid4vp::HolderBuilder;
use std::sync::Arc;

use crate::common::{Error, Result};
use crate::http::{HttpClient, WrappedHttpClient};
use crate::kms::{Kms, WrappedKms};
use crate::nonce::{NonceHandler, WrappedNonceHandler};
use crate::vault::{Vault, WrappedVault};
use crate::vc::oid4vp::holder::OID4VPHolder;

#[derive(uniffi::Object)]
struct OID4VPHolderBuilder {
    kms: WrappedKms,
    vault: WrappedVault,
    client_id: String,
    http_client: WrappedHttpClient,
    nonce_handler: Option<WrappedNonceHandler>,
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VPHolderBuilder {
    #[uniffi::constructor]
    pub fn new(
        kms: Arc<dyn Kms>,
        vault: Arc<dyn Vault>,
        client_id: String,
        http_client: Arc<dyn HttpClient>,
        nonce_handler: Option<Arc<dyn NonceHandler>>,
    ) -> OID4VPHolderBuilder {
        OID4VPHolderBuilder {
            kms: WrappedKms::new(kms),
            vault: WrappedVault::new(vault),
            client_id,
            http_client: WrappedHttpClient::new(http_client),
            nonce_handler: nonce_handler.map(WrappedNonceHandler::new),
        }
    }

    pub async fn build(&self) -> Result<OID4VPHolder> {
        let mut builder = HolderBuilder::new(
            self.kms.clone(),
            self.vault.clone(),
            self.client_id.to_owned(),
        )
        .with_http_client(self.http_client.to_owned());
        if let Some(nonce_handler) = self.nonce_handler.clone() {
            builder = builder.with_nonce_handler(Box::new(nonce_handler.to_owned()));
        }

        let holder = builder
            .build()
            .await
            .map_err(|e| Error::OID4VPHolder(e.to_string()))?;

        Ok(OID4VPHolder::new(holder))
    }
}
