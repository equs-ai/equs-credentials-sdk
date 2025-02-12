#[cfg(debug_assertions)]
use agent_sdk::reqwest::builder::ReqwestClientBuilder;

use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{HolderBuilder, IssuerBuilder, IssuerDiscovery};
use napi::{Either, Error, Result};
use napi_derive::napi;
use std::collections::HashMap;

use crate::kms::NativeKms;
use crate::kms::{JsKms, UnifiedKms};
use crate::nonce::{JsNonceGenerator, NativeNonceGenerator, UnifiedNonceGenerator};
use crate::utils::{from_json_object, parse_url_arg};
use crate::vault::{JsVault, NativeVault, UnifiedVault};
use crate::vc::core::JsKeyMetadata;
use crate::vc::oid4vci::holder::OID4VCIHolder;
use crate::vc::oid4vci::issuer::OID4VCIIssuer;
use crate::vc::JsonObject;

#[napi]
pub struct OID4VCIIssuerBuilder {
    kms: UnifiedKms,
    nonce_generator: UnifiedNonceGenerator,
    issuer_metadata: JsonObject,
    key_metadata: KeyMetadata,
    token_validation: Option<TokenValidation>,
    clock_skew: Option<time::Duration>,
    dedicated_keys: HashMap<String, KeyMetadata>,
}

#[napi]
impl OID4VCIIssuerBuilder {
    #[napi(constructor)]
    pub fn new(
        kms: Either<&NativeKms, JsKms>,
        nonce_generator: Either<&NativeNonceGenerator, JsNonceGenerator>,
        #[napi(ts_arg_type = "OID4VCIIssuerMetadata")] issuer_metadata: JsonObject,
        key_metadata: JsKeyMetadata,
    ) -> Self {
        OID4VCIIssuerBuilder {
            kms: kms.into(),
            nonce_generator: nonce_generator.into(),
            issuer_metadata,
            key_metadata: key_metadata.into(),
            token_validation: None,
            clock_skew: None,
            dedicated_keys: HashMap::new(),
        }
    }

    #[napi]
    pub fn token_validation_introspect(&mut self, url: String, header: Option<String>) {
        self.token_validation = Some(TokenValidation::Introspect(url, header));
    }

    #[napi]
    pub fn token_validation_jwks(&mut self, url: String) {
        self.token_validation = Some(TokenValidation::Jwks(url));
    }

    #[napi]
    pub fn with_clock_skew(&mut self, duration: i64) {
        self.clock_skew = Some(time::Duration::seconds(duration))
    }

    #[napi]
    pub fn with_dedicated_key_metadata(
        &mut self,
        credential_configuration_id: String,
        key_metadata: JsKeyMetadata,
    ) {
        self.dedicated_keys
            .insert(credential_configuration_id, key_metadata.into());
    }

    #[napi]
    pub async fn build(&self) -> Result<OID4VCIIssuer> {
        let mut builder = IssuerBuilder::new(
            self.kms.clone(),
            self.nonce_generator.clone(),
            from_json_object(self.issuer_metadata.clone())?,
            self.key_metadata.clone(),
        );

        if let Some(validation) = &self.token_validation {
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

        if let Some(duration) = self.clock_skew {
            builder = builder.with_clock_skew(duration);
        }

        for (key, value) in &self.dedicated_keys {
            builder = builder.with_dedicated_key_metadata(key, value);
        }

        let issuer = builder
            .build()
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(OID4VCIIssuer(Box::new(issuer)))
    }
}

#[derive(Clone)]
#[napi(js_name = "IssuerDiscovery")]
pub struct JsIssuerDiscovery(IssuerDiscovery);

#[napi]
impl JsIssuerDiscovery {
    #[napi(factory)]
    pub fn from_url(url: String) -> Self {
        JsIssuerDiscovery(IssuerDiscovery::Url(url))
    }

    #[napi(factory)]
    pub fn from_offer(
        #[napi(ts_arg_type = "OID4VCICredentialOffer")] credential_offer: JsonObject,
    ) -> Result<Self> {
        let credential_offer = from_json_object(credential_offer)?;

        Ok(JsIssuerDiscovery(IssuerDiscovery::Offer(credential_offer)))
    }

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

enum TokenValidation {
    Introspect(String, Option<String>),
    Jwks(String),
}

#[napi]
pub async fn _build_vci_holder(
    kms: Either<&NativeKms, JsKms>,
    vault: Either<&NativeVault, JsVault>,
    client_id: String,
    issuer_discovery: &JsIssuerDiscovery,
    redirect_url: Option<String>,
) -> Result<OID4VCIHolder> {
    let kms: UnifiedKms = kms.into();
    let vault: UnifiedVault = vault.into();
    let mut builder = HolderBuilder::new(kms, vault, client_id, issuer_discovery.0.to_owned());

    #[cfg(debug_assertions)]
    {
        builder = builder.with_http_client(
            ReqwestClientBuilder::new()
                .insecure()
                .build()
                .map_err(|err| Error::from_reason(format!("{:?}", err)))?,
        )
    }

    if let Some(url) = redirect_url {
        builder = builder.with_redirect_url(url.to_string());
    }

    let holder = builder
        .build()
        .await
        .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

    Ok(OID4VCIHolder::from_holder(holder))
}
