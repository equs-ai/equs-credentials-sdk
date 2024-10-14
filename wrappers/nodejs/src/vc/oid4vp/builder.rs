use crate::kms::NativeKms;
use crate::nonce::NativeNonceGenerator;
use crate::utils::from_json_object;
use crate::vault::NativeVault;
use crate::vc::core::JsKeyMetadata;
use crate::vc::oid4vp::holder::OID4VPHolder;
use crate::vc::oid4vp::verifier::OID4VPVerifier;
use crate::vc::JsonObject;
use agent_sdk::reqwest::ReqwestClient;
use agent_sdk::vc::oid4vp::{ClientMetadata, HolderBuilder, VerifierBuilder};
use napi::{Error, Result, Status};
use napi_derive::napi;

#[napi]
pub struct OID4VPVerifierBuilder {
    kms: NativeKms,
    nonce_generator: NativeNonceGenerator,
    key_metadata: JsKeyMetadata,
    client_id: String,
    client_metadata: Option<JsonObject>,
}

#[napi]
impl OID4VPVerifierBuilder {
    #[napi(constructor)]
    pub fn new(
        kms: &NativeKms,
        nonce_generator: &NativeNonceGenerator,
        key_metadata: JsKeyMetadata,
        client_id: String,
    ) -> Self {
        OID4VPVerifierBuilder {
            kms: kms.clone(),
            nonce_generator: nonce_generator.clone(),
            key_metadata,
            client_id,
            client_metadata: None,
        }
    }

    #[napi]
    pub fn with_client_metadata(&mut self, client_metadata: JsonObject) {
        self.client_metadata = Some(client_metadata);
    }

    #[napi]
    pub async fn build(&self) -> Result<OID4VPVerifier> {
        let mut builder = VerifierBuilder::new(
            self.kms.clone(),
            self.nonce_generator.clone(),
            self.key_metadata.clone().into(),
            self.client_id.clone(),
        );

        if let Some(client_metadata) = &self.client_metadata {
            builder = builder.with_client_metadata(
                ClientMetadata::try_from(from_json_object::<serde_json::Value>(
                    client_metadata.clone(),
                )?)
                .map_err(|err| Error::new(Status::InvalidArg, err))?,
            );
        }

        let verifier = builder
            .build()
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(OID4VPVerifier::from_verifier(verifier))
    }
}

#[napi]
pub struct OID4VPHolderBuilder {
    kms: NativeKms,
    vault: NativeVault,
    client_id: String,
    wallet_metadata: Option<JsonObject>,
}

#[napi]
impl OID4VPHolderBuilder {
    #[napi(constructor)]
    pub fn new(kms: &NativeKms, vault: &NativeVault, client_id: String) -> Self {
        OID4VPHolderBuilder {
            kms: kms.clone(),
            vault: vault.clone(),
            client_id,
            wallet_metadata: None,
        }
    }

    #[napi]
    pub fn with_wallet_metadata(&mut self, wallet_metadata: JsonObject) {
        self.wallet_metadata = Some(wallet_metadata)
    }

    #[napi]
    pub async fn build(&self) -> Result<OID4VPHolder> {
        let mut builder =
            HolderBuilder::new(self.kms.clone(), self.vault.clone(), self.client_id.clone());

        if cfg!(debug_assertions) {
            builder = builder.with_http_client(
                ReqwestClient::unsecure()
                    .map_err(|err| Error::from_reason(format!("{:?}", err)))?,
            )
        }

        if let Some(wallet_metadata) = &self.wallet_metadata {
            builder = builder.with_wallet_metadata(from_json_object(wallet_metadata.clone())?)
        }

        let holder = builder
            .build()
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(OID4VPHolder::from_holder(holder))
    }
}
