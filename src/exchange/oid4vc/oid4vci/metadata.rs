use std::collections::HashMap;

use oid4vci::core::metadata::IssuerMetadata;
use oid4vci::core::profiles::CoreProfilesMetadata;

use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{CredentialDefinition, CredentialDefinitionData, KeyMetadata};

pub type CredentialMetadata = oid4vci::metadata::CredentialMetadata<CoreProfilesMetadata>;

pub fn convert_metadata(issuer_metadata: &IssuerMetadata, key_metadata: KeyMetadata) -> facade_low_level::IssuerMetadata {
    let cred_defs = issuer_metadata
        .credential_configurations_supported()
        .iter()
        .map(|(id, cm)| cred_definition(id, cm))
        .collect();

    let converted = facade_low_level::IssuerMetadata {
        issuer_id: issuer_metadata.credential_issuer().to_string(),
        cred_defs,
        protocol_data: None,
        key_metadata,
    };

    converted
}

fn cred_definition(id: &String, credential_metadata: &oid4vci::metadata::CredentialMetadata<CoreProfilesMetadata>) -> CredentialDefinition {
    let disclosures = match credential_metadata.additional_fields() {
        CoreProfilesMetadata::SDJWTVC(metadata) => metadata.credential_definition()
            .claims()
            .unwrap_or(&HashMap::new())
            .keys()
            .map(|k| format!("$.{}", k.to_owned()))
            .collect(),
        _ => vec![],
    };

    let proofs = credential_metadata.proof_types_supported().unwrap_or(&HashMap::new())
        .keys()
        .map(|k| serde_json::to_string(k).unwrap_or("".to_string()))
        .collect();

    CredentialDefinition {
        cred_def_id: id.to_string(),
        format: credential_profile_metadata_format(
            credential_metadata.additional_fields(),
        ),
        claims: Default::default(),
        supported_proofs: proofs,
        display: None,
        protocol_data: Some(
            CredentialDefinitionData {
                disclosures,
                lifetime: None,
            }
        ),
        key_metadata: None,
    }
}

fn credential_profile_metadata_format(profile: &CoreProfilesMetadata) -> String {
    match profile {
        CoreProfilesMetadata::SDJWTVC(_) => { "vc+sd-jwt".to_string() }
        CoreProfilesMetadata::JWTVC(_) => { "jwt_vc_json".to_string() }
        CoreProfilesMetadata::JWTLDVC(_) => { "jwt_vc_json-ld".to_string() }
        CoreProfilesMetadata::LDVC(_) => { " ldp_vc".to_string() }
        CoreProfilesMetadata::ISOmDL(_) => { "mso_mdoc".to_string() }
    }
}