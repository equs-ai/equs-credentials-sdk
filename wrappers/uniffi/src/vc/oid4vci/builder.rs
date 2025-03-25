use crate::common::{Error, JsonValue, Result};
use crate::inmem::kms::InMemKms;
use crate::inmem::vault::InMemVault;
use crate::vc::oid4vci::holder::OID4VCIHolder;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use uniffi::custom_type;

pub type IssuerDiscovery = agent_sdk::vc::oid4vci::IssuerDiscovery;

#[derive(uniffi::Enum)]
pub enum IssuerDiscoveryEnum {
    Url(String),
    Offer(JsonValue),
    Metadata {
        issuer_metadata: JsonValue,
        authorization_metadata: JsonValue,
    },
}

custom_type!(IssuerDiscovery, IssuerDiscoveryEnum, {
    remote,
    lower: |issuer_discovery| match issuer_discovery {
            IssuerDiscovery::Url(url) => IssuerDiscoveryEnum::Url(url),
            IssuerDiscovery::Offer(offer) => {
                let offer = serde_json::to_value(offer).expect("Unable serialize Credential Offer");

                IssuerDiscoveryEnum::Offer(offer)
            }
            IssuerDiscovery::Metadata(issuer_metadata, authorization_metadata) => {
                let issuer_metadata = serde_json::to_value(issuer_metadata)
                    .expect("Unable serialize Issuer Metadata");
                let authorization_metadata = serde_json::to_value(authorization_metadata)
                    .expect("Unable serialize Authorization Metadata");

                IssuerDiscoveryEnum::Metadata {
                    issuer_metadata,
                    authorization_metadata,
                }
            }
        },
    try_lift: |issuer_discovery| match issuer_discovery {
        IssuerDiscoveryEnum::Url(url) => Ok(IssuerDiscovery::Url(url)),
        IssuerDiscoveryEnum::Offer(offer) => {
            let offer = serde_json::from_value(offer)?;

            Ok(IssuerDiscovery::Offer(offer))
        }
        IssuerDiscoveryEnum::Metadata { issuer_metadata, authorization_metadata } => {
            let issuer_metadata = serde_json::from_value(issuer_metadata)?;
            let authorization_metadata = serde_json::from_value(authorization_metadata)?;

            Ok(IssuerDiscovery::Metadata(issuer_metadata, authorization_metadata))
        }
    },
});

#[derive(uniffi::Object)]
struct OID4VCIHolderBuilder {
    kms: LocalKms,
    vault: agent_sdk::inmem::vault::InMemVault,
    client_id: String,
    issuer_discovery: IssuerDiscovery,
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VCIHolderBuilder {
    #[uniffi::constructor]
    pub fn new(
        kms: &InMemKms,
        vault: &InMemVault,
        client_id: String,
        issuer_discovery: IssuerDiscovery,
    ) -> OID4VCIHolderBuilder {
        OID4VCIHolderBuilder {
            kms: kms.inner(),
            vault: vault.inner(),
            client_id,
            issuer_discovery,
        }
    }

    pub async fn build(&self) -> Result<OID4VCIHolder> {
        let holder = agent_sdk::vc::oid4vci::HolderBuilder::new(
            self.kms.clone(),
            self.vault.clone(),
            self.client_id.to_owned(),
            self.issuer_discovery.clone(),
        )
        .with_http_client(
            ReqwestClientBuilder::new()
                .insecure()
                .build()
                .map_err(|e| Error::OID4VCIInternal(e.to_string()))?,
        )
        .build()
        .await
        .map_err(|e| Error::OID4VPHolder(e.to_string()))?;

        Ok(OID4VCIHolder::new(holder))
    }
}
