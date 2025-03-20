#[cfg(debug_assertions)]
use agent_sdk::reqwest::builder::ReqwestClientBuilder;

use crate::kms::JsKms;
use crate::nonce::JsNonceGenerator;
use crate::utils::from_json_object;
use crate::vault::JsVault;
use crate::vc::core::JsKeyMetadata;
use crate::vc::oid4vci::JsDuration;
use crate::vc::oid4vp::holder::OID4VPHolder;
use crate::vc::oid4vp::verifier::OID4VPVerifier;
use crate::vc::JsonObject;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vp::ClientMetadata;
use napi::{Error, Result, Status};
use napi_derive::napi;

#[napi]
pub async fn _build_vp_verifier(
    kms: JsKms,
    nonce_generator: JsNonceGenerator,
    key_metadata: JsKeyMetadata,
    client_id: String,
    #[napi(ts_arg_type = "ClientMetadata | null | undefined")] client_metadata: Option<JsonObject>,
) -> Result<OID4VPVerifier> {
    let key_metadata: KeyMetadata = key_metadata.into();
    let mut builder =
        agent_sdk::vc::oid4vp::VerifierBuilder::new(kms, nonce_generator, key_metadata, client_id);

    #[cfg(debug_assertions)]
    {
        builder = builder.with_http_client(
            ReqwestClientBuilder::new()
                .insecure() // TODO: is it ok?
                .build()
                .map_err(|err| Error::from_reason(format!("{:?}", err)))?,
        )
    }

    if let Some(client_metadata) = &client_metadata {
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

#[napi]
pub async fn _build_vp_holder(
    kms: JsKms,
    vault: JsVault,
    client_id: String,
    #[napi(ts_arg_type = "WalletMetadata | null | undefined")] wallet_metadata: Option<JsonObject>,
    pop_lifetime: Option<JsDuration>,
) -> Result<OID4VPHolder> {
    let mut builder = agent_sdk::vc::oid4vp::HolderBuilder::new(kms, vault, client_id);

    #[cfg(debug_assertions)]
    {
        builder = builder.with_http_client(
            ReqwestClientBuilder::new()
                .insecure()
                .build()
                .map_err(|err| Error::from_reason(format!("{:?}", err)))?,
        )
    }

    if let Some(wallet_metadata) = &wallet_metadata {
        builder = builder.with_wallet_metadata(serde_json::from_value(from_json_object(
            wallet_metadata.clone(),
        )?)?)
    }
    if let Some(duration) = pop_lifetime {
        builder = builder.with_pop_lifetime(duration.try_into()?);
    }

    let holder = builder
        .build()
        .await
        .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

    Ok(OID4VPHolder::from_holder(holder))
}
