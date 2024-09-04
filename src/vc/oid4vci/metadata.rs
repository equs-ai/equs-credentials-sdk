use std::collections::HashMap;

use oid4vci::core::metadata::IssuerMetadata;
use oid4vci::core::profiles::{CoreProfilesMetadata, CoreProfilesRequest, CoreProfilesResponse};

use crate::vc;
use crate::vc::core::{CredentialDefinition, CredentialDefinitionData, KeyMetadata};
use crate::vc::{HasVCFormat, VCFormat};

pub type CredentialMetadata = oid4vci::metadata::CredentialMetadata<CoreProfilesMetadata>;

pub fn convert_metadata(issuer_metadata: &IssuerMetadata, key_metadata: KeyMetadata) -> vc::core::IssuerMetadata {
    let cred_defs = issuer_metadata
        .credential_configurations_supported()
        .iter()
        .map(|(id, cm)| cred_definition(id, cm))
        .collect();

    let converted = vc::core::IssuerMetadata {
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
        format: credential_metadata.additional_fields().format(),
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

impl HasVCFormat for CoreProfilesRequest {
    fn format(&self) -> VCFormat {
        match self {
            CoreProfilesRequest::SDJWTVC(_) => VCFormat::SdJwtVc,
            CoreProfilesRequest::JWTVC(_) => VCFormat::JwtVcJson,
            CoreProfilesRequest::JWTLDVC(_) => VCFormat::JwtVcJsonLD,
            CoreProfilesRequest::LDVC(_) => VCFormat::LdpVc,
            CoreProfilesRequest::ISOmDL(_) => VCFormat::MsoMdoc,
        }
    }
}

impl HasVCFormat for CoreProfilesResponse {
    fn format(&self) -> VCFormat {
        match self {
            CoreProfilesResponse::SDJWTVC(_) => VCFormat::SdJwtVc,
            CoreProfilesResponse::JWTVC(_) => VCFormat::JwtVcJson,
            CoreProfilesResponse::JWTLDVC(_) => VCFormat::JwtVcJsonLD,
            CoreProfilesResponse::LDVC(_) => VCFormat::LdpVc,
            CoreProfilesResponse::ISOmDL(_) => VCFormat::MsoMdoc,
        }
    }
}

impl HasVCFormat for CoreProfilesMetadata {
    fn format(&self) -> crate::vc::VCFormat {
        match self {
            CoreProfilesMetadata::SDJWTVC(_) => VCFormat::SdJwtVc,
            CoreProfilesMetadata::JWTVC(_) => VCFormat::JwtVcJson,
            CoreProfilesMetadata::JWTLDVC(_) => VCFormat::JwtVcJsonLD,
            CoreProfilesMetadata::LDVC(_) => VCFormat::LdpVc,
            CoreProfilesMetadata::ISOmDL(_) => VCFormat::MsoMdoc,
        }
    }
}