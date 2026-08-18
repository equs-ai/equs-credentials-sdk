use crate::did::JsDIDResolver;
use crate::http::ReqwestHttpClient;
use crate::kms::JsKms;
use crate::nonce::JsNonceHandler;
use crate::utils::from_json_object;
use crate::vault::JsVault;
use crate::vc::JsonObject;
use crate::vc::core::{JsKeyMetadata, JsProofOfPossessionMetadata};
use crate::vc::oid4vp::ClientId;
use crate::vc::oid4vp::holder::InnerOID4VPHolder;
use crate::vc::oid4vp::verifier::InternalOID4VPVerifier;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vp::ClientMetadata;
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Result, Status};
use napi_derive::napi;

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn _build_vp_verifier(
    kms: JsKms,
    nonce_generator: JsNonceHandler,
    key_metadata: JsKeyMetadata,
    client_id: &ClientId,
    #[napi(ts_arg_type = "ClientMetadata | null | undefined")] client_metadata: Option<JsonObject>,
    http_client: Option<&ReqwestHttpClient>,
    did_resolver: Option<JsDIDResolver>,
    trusted_root_certificates: Option<Vec<Uint8Array>>,
    x509_certificate_chain: Option<Uint8Array>,
) -> Result<InternalOID4VPVerifier> {
    let key_metadata: KeyMetadata = key_metadata.into();
    let mut builder = agent_sdk::vc::oid4vp::VerifierBuilder::new(
        kms,
        nonce_generator,
        key_metadata,
        client_id.0.clone(),
    );

    if let Some(client_metadata) = &client_metadata {
        builder = builder.with_client_metadata(
            ClientMetadata::try_from(from_json_object::<serde_json::Value>(
                client_metadata.clone(),
            )?)
            .map_err(|err| Error::new(Status::InvalidArg, err))?,
        );
    }
    if let Some(did_resolver) = did_resolver {
        builder = builder.with_did_resolver(did_resolver).unwrap();
    }

    if let Some(http_client) = http_client {
        builder = builder.with_http_client(http_client.inner())
    }

    if let Some(trusted_root_certificates) = trusted_root_certificates {
        for cert in trusted_root_certificates {
            builder = builder
                .add_trusted_root_certificate(&cert)
                .map_err(|err| Error::new(Status::InvalidArg, err))?;
        }
    }

    if let Some(x509_certificate_chain) = x509_certificate_chain {
        builder = builder
            .with_x509_certificate_chain(&x509_certificate_chain)
            .map_err(|err| Error::new(Status::InvalidArg, err))?;
    }

    let verifier = builder
        .build()
        .await
        .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

    Ok(InternalOID4VPVerifier::from_verifier(verifier))
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn _build_vp_holder(
    kms: JsKms,
    vault: JsVault,
    client_id: String,
    #[napi(ts_arg_type = "WalletMetadata | null | undefined")] wallet_metadata: Option<JsonObject>,
    http_client: &ReqwestHttpClient,
    pop: Option<JsProofOfPossessionMetadata>,
    did_resolver: Option<JsDIDResolver>,
    nonce_handler: Option<JsNonceHandler>,
) -> Result<InnerOID4VPHolder> {
    let mut builder =
        agent_sdk::vc::oid4vp::HolderBuilder::new(kms, vault, client_id, http_client.inner());

    if let Some(wallet_metadata) = &wallet_metadata {
        builder = builder.with_wallet_metadata(serde_json::from_value(from_json_object(
            wallet_metadata.clone(),
        )?)?)
    }

    if let Some(js_pop) = pop {
        builder = builder.with_pop(js_pop.try_into()?);
    }

    if let Some(did_resolver) = did_resolver {
        builder = builder.with_did_resolver(did_resolver).unwrap();
    }

    if let Some(nonce_handler) = nonce_handler {
        builder = builder.with_nonce_handler(Box::new(nonce_handler));
    }
    let holder = builder
        .build()
        .await
        .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

    Ok(InnerOID4VPHolder::from_holder(holder))
}
