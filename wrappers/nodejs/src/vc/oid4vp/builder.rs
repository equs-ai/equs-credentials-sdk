use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vc::oid4vp::{ClientMetadata, HolderBuilder, VerifierBuilder};
use napi::{Either, Error, Result, Status};
use napi_derive::napi;

use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::nonce::{JsNonceGenerator, NativeNonceGenerator, UnifiedNonceGenerator};
use crate::utils::from_json_object;
use crate::vault::{JsVault, NativeVault, UnifiedVault};
use crate::vc::core::JsKeyMetadata;
use crate::vc::oid4vp::holder::OID4VPHolder;
use crate::vc::oid4vp::verifier::OID4VPVerifier;
use crate::vc::JsonObject;

#[napi]
pub struct OID4VPVerifierBuilder {
    kms: UnifiedKms,
    nonce_generator: UnifiedNonceGenerator,
    key_metadata: JsKeyMetadata,
    client_id: String,
    client_metadata: Option<JsonObject>,
}

#[napi]
impl OID4VPVerifierBuilder {
    #[napi(constructor)]
    pub fn new(
        kms: Either<&NativeKms, JsKms>,
        nonce_generator: Either<&NativeNonceGenerator, JsNonceGenerator>,
        key_metadata: JsKeyMetadata,
        client_id: String,
    ) -> Self {
        OID4VPVerifierBuilder {
            kms: kms.into(),
            nonce_generator: nonce_generator.into(),
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
    kms: UnifiedKms,
    vault: UnifiedVault,
    client_id: String,
    wallet_metadata: Option<JsonObject>,
}

#[napi]
impl OID4VPHolderBuilder {
    #[napi(constructor)]
    pub fn new(
        kms: Either<&NativeKms, JsKms>,
        vault: Either<&NativeVault, JsVault>,
        client_id: String,
    ) -> Self {
        OID4VPHolderBuilder {
            kms: kms.into(),
            vault: vault.into(),
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
                ReqwestClientBuilder::new()
                    .insecure()
                    .build()
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
