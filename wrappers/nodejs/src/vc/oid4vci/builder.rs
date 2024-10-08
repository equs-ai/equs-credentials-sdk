use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{CredentialOffer, HolderBuilder, IssuerBuilder, IssuerDiscovery};
use napi::{Error, Result};
use napi_derive::napi;
use std::collections::HashMap;

use crate::kms::NativeKms;
use crate::nonce::NativeNonceGenerator;
use crate::utils::{parse_string_arg, parse_url_arg};
use crate::vault::NativeVault;
use crate::vc::core::JsKeyMetadata;
use crate::vc::oid4vci::holder::JsHolder;
use crate::vc::oid4vci::issuer::JsIssuer;

#[napi(js_name = "IssuerBuilder")]
pub struct JsIssuerBuilder {
    kms: NativeKms,
    nonce_generator: NativeNonceGenerator,
    issuer_metadata: String,
    key_metadata: KeyMetadata,
    token_validation: Option<TokenValidation>,
    dedicated_keys: HashMap<String, KeyMetadata>,
}

#[napi]
impl JsIssuerBuilder {
    #[napi(constructor)]
    pub fn new(
        kms: &NativeKms,
        nonce_generator: &NativeNonceGenerator,
        issuer_metadata: String,
        key_metadata: JsKeyMetadata,
    ) -> Self {
        JsIssuerBuilder {
            kms: kms.clone(),
            nonce_generator: nonce_generator.clone(),
            issuer_metadata,
            key_metadata: key_metadata.into(),
            token_validation: None,
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
    pub fn with_dedicated_key_metadata(
        &mut self,
        credential_configuration_id: String,
        key_metadata: JsKeyMetadata,
    ) {
        self.dedicated_keys
            .insert(credential_configuration_id, key_metadata.into());
    }

    #[napi]
    pub async fn build(&self) -> Result<JsIssuer> {
        let mut builder = IssuerBuilder::new(
            self.kms.clone(),
            self.nonce_generator.clone(),
            parse_string_arg(&self.issuer_metadata)?,
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

        for (key, value) in &self.dedicated_keys {
            builder = builder.with_dedicated_key_metadata(key, value);
        }

        let issuer = builder
            .build()
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(JsIssuer(Box::new(issuer)))
    }
}

#[napi(js_name = "HolderBuilder")]
pub struct JsHolderBuilder {
    kms: NativeKms,
    vault: NativeVault,
    client_id: String,
    issuer_discovery: JsIssuerDiscovery,
    redirect_url: Option<String>,
}

#[napi]
impl JsHolderBuilder {
    #[napi(constructor)]
    pub fn new(
        kms: &NativeKms,
        vault: &NativeVault,
        client_id: String,
        issuer_discovery: &JsIssuerDiscovery,
    ) -> Self {
        JsHolderBuilder {
            kms: kms.clone(),
            vault: vault.clone(),
            client_id,
            issuer_discovery: issuer_discovery.clone(),
            redirect_url: None,
        }
    }

    #[napi]
    pub fn with_redirect_url(&mut self, redirect_url: String) {
        self.redirect_url = Some(redirect_url);
    }

    #[napi]
    pub async fn build(&self) -> Result<JsHolder> {
        let mut builder = HolderBuilder::new(
            self.kms.clone(),
            self.vault.clone(),
            self.client_id.to_owned(),
            self.issuer_discovery.0.clone(),
        );

        if let Some(url) = &self.redirect_url {
            builder = builder.with_redirect_url(url.to_string());
        }

        let holder = builder
            .build()
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(JsHolder::from_holder(holder))
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
    pub fn from_offer(credential_offer: String) -> Result<Self> {
        let credential_offer = parse_string_arg(&credential_offer)?;

        Ok(JsIssuerDiscovery(IssuerDiscovery::Offer(
            CredentialOffer::Value { credential_offer },
        )))
    }

    #[napi(factory)]
    pub fn from_offer_uri(credential_offer_uri: String) -> Result<Self> {
        let credential_offer_uri = parse_url_arg(&credential_offer_uri)?;

        Ok(JsIssuerDiscovery(IssuerDiscovery::Offer(
            CredentialOffer::Reference {
                credential_offer_uri,
            },
        )))
    }

    #[napi(factory)]
    pub fn from_metadata(issuer_metadata: String, auth_metadata: String) -> Result<Self> {
        Ok(JsIssuerDiscovery(IssuerDiscovery::Metadata(
            parse_string_arg(&issuer_metadata)?,
            parse_string_arg(&auth_metadata)?,
        )))
    }
}

enum TokenValidation {
    Introspect(String, Option<String>),
    Jwks(String),
}
