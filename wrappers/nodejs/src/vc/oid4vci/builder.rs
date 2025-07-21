use crate::did::JsDIDResolver;
use crate::http::ReqwestHttpClient;
use crate::kms::JsKms;
use crate::nonce::JsNonceHandler;
use crate::utils::{from_json_object, parse_url_arg};
use crate::vault::JsVault;
use crate::vc::JsonObject;
use crate::vc::core::JsKeyMetadata;
use crate::vc::oid4vci::holder::OID4VCIHolder;
use crate::vc::oid4vci::issuer::OID4VCIIssuer;
use crate::vc::oid4vci::{JsDuration, JsTokenValidation};
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{HolderBuilder, IssuerBuilder, IssuerDiscovery, IssuerMetadata};
use napi::{Error, Result};
use napi_derive::napi;
use std::collections::HashMap;

/// An enum containing options of discovery of the `Issuer` for a `Holder`
///
/// @property fromUrl - {@link IssuerDiscovery.fromUrl}
/// @property fromOffer - {@link IssuerDiscovery.fromOffer}
/// @property fromMetadata - {@link IssuerDiscovery.fromMetadata}
#[derive(Clone)]
#[napi(js_name = "IssuerDiscovery")]
pub struct JsIssuerDiscovery(IssuerDiscovery);

#[napi]
impl JsIssuerDiscovery {
    /// Creates `IssuerDiscovery` from url
    ///
    /// @param {string} url - issuer url
    #[napi(factory)]
    pub fn from_url(url: String) -> Self {
        JsIssuerDiscovery(IssuerDiscovery::Url(url))
    }

    /// Creates `IssuerDiscovery` from {@link OID4VCICredentialOffer}
    ///
    /// @param {OID4VCICredentialOffer} credentialOffer - credential offer
    #[napi(factory)]
    pub fn from_offer(
        #[napi(ts_arg_type = "OID4VCICredentialOffer")] credential_offer: JsonObject,
    ) -> Result<Self> {
        let credential_offer = from_json_object(credential_offer)?;

        Ok(JsIssuerDiscovery(IssuerDiscovery::Offer(credential_offer)))
    }

    /// Creates `IssuerDiscovery` from {@link OID4VCIIssuerMetadata} and {@link AuthMetadata}
    ///
    /// @param {OID4VCIIssuerMetadata} issuerMetadata - issuer metadata
    /// @param {AuthMetadata} authMetadata - authorization metadata
    #[napi(
        factory,
        ts_args_type = "issuerMetadata: OID4VCIIssuerMetadata, authMetadata: AuthMetadata"
    )]
    pub fn from_metadata(issuer_metadata: JsonObject, auth_metadata: JsonObject) -> Result<Self> {
        Ok(JsIssuerDiscovery(IssuerDiscovery::Metadata(
            from_json_object(issuer_metadata)?,
            from_json_object(auth_metadata)?,
        )))
    }
}

pub enum TokenValidation {
    Introspect(String, Option<String>),
    Jwks(String),
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn _build_vci_holder(
    kms: JsKms,
    vault: JsVault,
    client_id: String,
    issuer_discovery: &JsIssuerDiscovery,
    redirect_url: Option<String>,
    http_client: &ReqwestHttpClient,
    pop_lifetime: Option<JsDuration>,
    did_resolver: Option<JsDIDResolver>,
) -> Result<OID4VCIHolder> {
    let mut builder = HolderBuilder::new(
        kms,
        vault,
        client_id,
        issuer_discovery.0.to_owned(),
        http_client.inner(),
    );

    if let Some(url) = redirect_url {
        builder = builder.with_redirect_url(url.to_string());
    }

    if let Some(duration) = pop_lifetime {
        builder = builder.with_pop_lifetime(duration.try_into()?);
    }

    if let Some(did_resolver) = did_resolver {
        builder = builder.with_did_resolver(did_resolver).unwrap();
    }

    let holder = builder
        .build()
        .await
        .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
    Ok(OID4VCIHolder::from_holder(holder))
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn _build_vci_issuer(
    kms: JsKms,
    nonce_handler: Option<JsNonceHandler>,
    #[napi(ts_arg_type = "OID4VCIIssuerMetadata")] issuer_metadata: JsonObject,
    key_metadata: JsKeyMetadata,
    token_validation: Option<JsTokenValidation>,
    clock_skew: Option<JsDuration>,
    dedicated_keys: HashMap<String, JsKeyMetadata>,
    cred_lifetime: Option<JsDuration>,
    cred_lifetime_per_cred_conf_id: HashMap<String, JsDuration>,
    did_resolver: Option<JsDIDResolver>,
    http_client: Option<&ReqwestHttpClient>,
) -> Result<OID4VCIIssuer> {
    let issuer_metadata: IssuerMetadata =
        serde_json::from_value(from_json_object(issuer_metadata)?)?;
    let key_metadata: KeyMetadata = key_metadata.into();
    let token_validation: Option<TokenValidation> = token_validation
        .map(TokenValidation::try_from)
        .transpose()?;
    let clock_skew: Option<time::Duration> =
        clock_skew.map(time::Duration::try_from).transpose()?;
    let mut builder = IssuerBuilder::new(kms, issuer_metadata, key_metadata);

    if let Some(cred_lifetime) = cred_lifetime {
        builder = builder.with_default_cred_lifetime(cred_lifetime.try_into()?);
    }

    for (cred_conf_id, lifetime) in cred_lifetime_per_cred_conf_id {
        builder = builder.with_credential_lifetime(cred_conf_id, lifetime.try_into()?);
    }

    if let Some(did_resolver) = did_resolver {
        builder = builder.with_did_resolver(did_resolver).unwrap();
    }

    if let Some(validation) = &token_validation {
        match validation {
            TokenValidation::Introspect(url, header) => {
                builder =
                    builder.token_validation_introspect(parse_url_arg(url)?, header.to_owned())
            }
            TokenValidation::Jwks(url) => {
                builder = builder.token_validation_jwks(parse_url_arg(url)?)
            }
        }
    }

    if let Some(duration) = clock_skew {
        builder = builder.with_clock_skew(duration);
    }

    for (key, value) in &dedicated_keys {
        builder = builder.with_dedicated_key_metadata(key, &value.clone().into());
    }

    if let Some(http_client) = http_client {
        builder = builder.with_http_client(http_client.inner());
    }

    if let Some(nonce_handler) = nonce_handler {
        let issuer = builder
            .with_nonce_handler(nonce_handler)
            .build()
            .await
            .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
        Ok(OID4VCIIssuer(Box::new(issuer)))
    } else {
        let issuer = builder
            .build()
            .await
            .map_err(|e| Error::from_reason(format!("{:?}", e)))?;
        Ok(OID4VCIIssuer(Box::new(issuer)))
    }
}
