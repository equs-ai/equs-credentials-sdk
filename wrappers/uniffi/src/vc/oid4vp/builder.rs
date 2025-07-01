use agent_sdk::vc::oid4vp::HolderBuilder;
use std::sync::Arc;

use crate::common::{Error, Result};
use crate::http::{HttpClient, WrappedHttpClient};
use crate::kms::{Kms, WrappedKms};
use crate::vault::{Vault, WrappedVault};
use crate::vc::oid4vp::holder::OID4VPHolder;

#[derive(uniffi::Object)]
struct OID4VPHolderBuilder {
    kms: WrappedKms,
    vault: WrappedVault,
    client_id: String,
    http_client: WrappedHttpClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VPHolderBuilder {
    #[uniffi::constructor]
    pub fn new(
        kms: Arc<dyn Kms>,
        vault: Arc<dyn Vault>,
        client_id: String,
        http_client: Arc<dyn HttpClient>,
    ) -> OID4VPHolderBuilder {
        OID4VPHolderBuilder {
            kms: WrappedKms::new(kms),
            vault: WrappedVault::new(vault),
            client_id,
            http_client: WrappedHttpClient::new(http_client),
        }
    }

    pub async fn build(&self) -> Result<OID4VPHolder> {
        let builder = HolderBuilder::new(
            self.kms.clone(),
            self.vault.clone(),
            self.client_id.to_owned(),
        )
        .with_http_client(self.http_client.to_owned());

        let holder = builder
            .build()
            .await
            .map_err(|e| Error::OID4VPHolder(e.to_string()))?;

        Ok(OID4VPHolder::new(holder))
    }
}
