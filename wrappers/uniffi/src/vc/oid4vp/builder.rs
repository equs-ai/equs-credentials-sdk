use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vc::oid4vp::HolderBuilder;

use crate::common::{Error, Result};
use crate::inmem::kms::InMemKms;
use crate::inmem::vault::InMemVault;
use crate::vc::oid4vp::holder::OID4VPHolder;

#[derive(uniffi::Object)]
struct OID4VPHolderBuilder {
    kms: LocalKms,
    vault: agent_sdk::inmem::vault::InMemVault,
    client_id: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VPHolderBuilder {
    #[uniffi::constructor]
    pub fn new(kms: &InMemKms, vault: &InMemVault, client_id: String) -> OID4VPHolderBuilder {
        OID4VPHolderBuilder {
            kms: kms.inner(),
            vault: vault.inner(),
            client_id,
        }
    }

    pub async fn build(&self) -> Result<OID4VPHolder> {
        let holder = HolderBuilder::new(
            self.kms.clone(),
            self.vault.clone(),
            self.client_id.to_owned(),
        )
        .with_http_client(
            ReqwestClientBuilder::new()
                .insecure()
                .build()
                .map_err(|e| Error::OID4VPHolder(e.to_string()))?,
        )
        .build()
        .await
        .map_err(|e| Error::OID4VPHolder(e.to_string()))?;

        Ok(OID4VPHolder::new(holder))
    }
}
