use oauth2::http::HeaderValue;

use crate::core_::kms;
use crate::exchange;
use crate::exchange::oid4vc::vci::IssuerMetadata;
use crate::exchange::oid4vc::vci_issuer::Oid4VciIssuer;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::CredentialDefinition;

pub struct IssuerService {
    oid4vci_issuer: Oid4VciIssuer,
}

impl IssuerService {
    pub fn new<KH>(
        kms: impl kms::Kms<KH> + 'static,
        metadata: IssuerMetadata,
        auth_server_admin_auth_header: Option<HeaderValue>,
        did_url: String,
        kid: String,
    ) -> Self
    where
        KH: kms::KeyHandle + 'static,
    {
        let cred_defs = retrieve_cred_defs(&metadata);

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
            Oid4VciIssuer::new(metadata, core_issuer, auth_server_admin_auth_header);

        Self { oid4vci_issuer }
    }

    // pub async fn create_issuer_metadata() -> Result<IssuerMetadata, Box<dyn Error>> {}
    //
    // pub async fn create_credential_offer(
    //     cred_def_id: &str,
    //     protocol_data: Option<&CredentialOfferData>, // grant type (auth code, pre-auth code), etc.
    // ) -> Result<CredentialOffer, Box<dyn Error>> {}
    //
    // pub async fn issue_credential(
    //     credential_request: &CredentialRequest,
    //     claims: &CredentialClaims,
    //     token: &AccessToken,
    // ) -> Result<(Credential, CredentialMetadata), Box<dyn Error>> {}
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
                format: exchange::oid4vc::vci::credential_profile_metadata_format(cm.additional_fields()),
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
