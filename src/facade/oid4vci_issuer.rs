use oauth2::http::HeaderValue;
use oid4vci::core::profiles::CoreProfilesOffer;
use oid4vci::credential_offer::{CredentialOfferGrants, CredentialOfferParameters};
use serde_json::{Value as Json, Value};
use url::Url;

use crate::core_::kms;
use crate::core_::storage::Storage;
use crate::exchange;
use crate::exchange::oid4vc::vci::{
    CredentialRequest, CredentialResponse, IssuerMetadata,
};
use crate::exchange::oid4vc::vci_issuer::Oid4VciIssuer;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::CredentialDefinition;
use crate::facade::oid4vci_issuer::Error::{Issuance, Parse};
use crate::impls::http::HttpClient;

pub struct IssuerService {
    oid4vci_issuer: Oid4VciIssuer,
    storage: Box<dyn Storage<String, Json>>,
    http_client: &'static HttpClient,
}

impl IssuerService {
    pub fn from_issuer_metadata<KH>(
        kms: impl kms::Kms<KH> + 'static,
        storage: impl Storage<String, Json> + 'static,
        http_client: &'static HttpClient,
        metadata: IssuerMetadata,
        did_url: String,
        kid: String,
        auth_server_admin_auth_header: Option<HeaderValue>,
    ) -> Self
    where
        KH: kms::KeyHandle + 'static,
    {
        let cred_defs = Self::retrieve_cred_defs(&metadata);

        let issuer_metadata = facade_low_level::IssuerMetadata {
            issuer_id: metadata.credential_issuer().to_string(),
            cred_defs,
            protocol_data: Some(facade_low_level::IssuerMetadataData::Oidc4Vc(
                metadata.clone(),
            )),
            key_metadata: facade_low_level::KeyMetadata { did_url, kid },
        };
        let core_issuer = facade_low_level::IssuerService::new(kms, issuer_metadata);
        let oid4vci_issuer =
            Oid4VciIssuer::new(metadata, core_issuer, http_client, auth_server_admin_auth_header);

        Self {
            oid4vci_issuer,
            storage: Box::new(storage),
            http_client,
        }
    }

    pub fn get_issuer_metadata(&self) -> Result<Json> {
        let metadata = self.oid4vci_issuer.metadata()?;

        return Ok(metadata);
    }

    pub async fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParameters<CoreProfilesOffer>, Url)> {
        let offer = self
            .oid4vci_issuer
            .create_credential_offer(cred_def_ids, grants)?;

        Ok(offer)
    }

    pub async fn issue_credential(
        &mut self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &Value,
    ) -> Result<CredentialResponse> {
        //TODO: Implement another option to get a nonce from the token
        if let Ok(nonce_value) = self.storage.get(token).await {
            let nonce = serde_json::from_value(nonce_value.to_owned())
                .map_err(Parse)?;

            let (cred, cred_metadata) = self.oid4vci_issuer
                .issue_credential(cred_request, token, nonce, claims)
                .await
                .map_err(Issuance)?;

            if let Some(value) = serde_json::to_value(&cred_metadata).ok() {
                let _ = self.storage.put(cred_metadata.core_metadata.id, value).await;
            }

            Ok(cred)
        } else {
            let (error, nonce) = self.oid4vci_issuer
                .generate_pop_verification_error_and_nonce();

            if let Ok(nonce) = serde_json::to_value(nonce) {
                let _ = self.storage.put(token.to_string(), nonce).await;
            }

            Err(Issuance(error))
        }
    }

    fn retrieve_cred_defs(metadata: &IssuerMetadata) -> Vec<CredentialDefinition> {
        metadata
            .credential_configurations_supported()
            .iter()
            .map(|(id, cm)| {
                let proofs: Vec<String> = if let Some(proof) = cm.proof_types_supported() {
                    proof
                        .keys()
                        .map(|k| serde_json::to_string(k).unwrap_or("".to_string()))
                        .collect()
                } else {
                    vec![]
                };

                CredentialDefinition {
                    cred_def_id: id.to_string(),
                    format: exchange::oid4vc::vci::credential_profile_metadata_format(
                        cm.additional_fields(),
                    ),
                    claims: Default::default(),
                    //TODO: Implement mapping from cm.additional_fields() to Some(Vec<String>)
                    credential_signing_alg_values_supported: None,
                    //TODO: Implement mapping from cm.additional_fields() to Some(Vec<String>)
                    cryptographic_binding_methods_supported: None,
                    supported_proofs: proofs,
                    display: facade_low_level::Display,
                    protocol_data: None,
                    key_metadata: None,
                }
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Issuance(#[from] exchange::oid4vc::vci_issuer::Error),
    #[error("Parsing error: {0}")]
    Parse(#[from] serde_json::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
