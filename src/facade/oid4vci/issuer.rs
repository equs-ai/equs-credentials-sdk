use async_trait::async_trait;
use oauth2::http::HeaderValue;
use oid4vci::core::profiles::{CoreProfilesMetadata, CoreProfilesOffer};
use oid4vci::credential_offer::{CredentialOfferGrants, CredentialOfferParameters};
use url::Url;

use crate::core_::kms;
use crate::core_::storage::Storage;
use crate::exchange;
use crate::exchange::oid4vc::oid4vci::{CredentialRequest, CredentialResponse, IssuerMetadata};
use crate::exchange::oid4vc::oid4vci::issuer::Oid4VciIssuer;
use crate::facade::{facade_low_level, facade_oid4vc};
use crate::facade::facade_low_level::{CredentialDefinition, CredentialDefinitionData};
use crate::facade::facade_oid4vc::CredentialClaims;
use crate::impls::http::HttpClient;

pub type Error = facade_oid4vc::Error;
pub type Result<T> = facade_oid4vc::Result<T>;

pub struct IssuerService {
    oid4vci_issuer: Oid4VciIssuer,
    storage: Box<dyn Storage<String, serde_json::Value>>,
    http_client: HttpClient,
}

#[async_trait]
impl facade_oid4vc::Issuer for IssuerService {
    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParameters<CoreProfilesOffer>, Url)> {
        let offer = self
            .oid4vci_issuer
            .create_credential_offer(cred_def_ids, grants)?;

        Ok(offer)
    }

    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.oid4vci_issuer.metadata()
    }

    async fn issue_credential(
        &mut self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &CredentialClaims,
    ) -> Result<CredentialResponse> {
        //TODO: Implement another option to get a nonce from the token
        if let Ok(nonce_value) = self.storage.get(token).await {
            let nonce = serde_json::from_value(nonce_value.to_owned())?;

            let (cred, cred_metadata) = self.oid4vci_issuer
                .issue_credential(cred_request, token, nonce, claims)
                .await?;

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

            Err(Error::Issuer(error))
        }
    }
}

impl IssuerService {
    pub fn from_issuer_metadata<KH>(
        kms: impl kms::Kms<KH> + 'static,
        storage: impl Storage<String, serde_json::Value> + 'static,
        http_client: HttpClient,
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
            Oid4VciIssuer::new(metadata, core_issuer, http_client.clone(), auth_server_admin_auth_header);

        Self {
            oid4vci_issuer,
            storage: Box::new(storage),
            http_client,
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
                //TODO Implement mapping for other credential types
                let disclosures: Vec<String> = if let CoreProfilesMetadata::SDJWTVC(metadata) = cm.additional_fields() {
                    metadata.credential_definition()
                        .claims()
                        .unwrap()
                        .keys()
                        .map(|k| format!("$.{}", k.to_owned()))
                        .collect()
                } else {
                    vec![]
                };

                CredentialDefinition {
                    cred_def_id: id.to_string(),
                    format: exchange::oid4vc::oid4vci::credential_profile_metadata_format(
                        cm.additional_fields(),
                    ),
                    claims: Default::default(),
                    supported_proofs: proofs,
                    display: None,
                    protocol_data: Some(
                        CredentialDefinitionData{
                            disclosures,
                            lifetime: None,
                        }
                    ),
                    key_metadata: None,
                }
            })
            .collect()
    }
}