use crate::crypto::Alg;
use crate::vc::core::{CredentialDefinition, CredentialDefinitionData, KeyMetadata};
use crate::vc::{pop, HasVCFormat, VCFormat};
use crate::{crypto, utils, vc};
use common_macros::DebugError;
use oid4vci::core::profiles;
use oid4vci::core::profiles::{CoreProfilesMetadata, CoreProfilesRequest, CoreProfilesResponse};
use oid4vci::proof_of_possession::KeyProofType;
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use tracing::{instrument, trace, Level};

pub type IssuerMetadata = oid4vci::core::metadata::IssuerMetadata;
pub type CredentialMetadata = oid4vci::metadata::CredentialMetadata<CoreProfilesMetadata>;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Crypto error at {location}"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
}

type Result<T> = std::result::Result<T, Error>;

#[instrument(
        level = Level::TRACE,
        err(),
        ret(),
)]
pub fn convert_metadata(
    issuer_metadata: &IssuerMetadata,
    cred_def_ids_with_key_metadata: &HashMap<String, KeyMetadata>,
    default_key_metadata: &KeyMetadata,
) -> Result<vc::core::IssuerMetadata> {
    let cred_defs = issuer_metadata
        .credential_configurations_supported()
        .iter()
        .map(|(id, cm)| {
            cred_definition(
                id,
                cm,
                cred_def_ids_with_key_metadata
                    .get(id)
                    .unwrap_or(default_key_metadata),
            )
        })
        .collect::<Result<Vec<CredentialDefinition>>>()?;

    trace!(resolved_cred_defs = ?cred_defs);

    let converted = vc::core::IssuerMetadata {
        issuer_id: issuer_metadata.credential_issuer().to_string(),
        cred_defs,
        protocol_data: None,
    };

    Ok(converted)
}

#[instrument(
        level = Level::TRACE,
        err(),
        ret(),
)]
pub fn cred_definition(
    id: &str,
    credential_metadata: &oid4vci::metadata::CredentialMetadata<CoreProfilesMetadata>,
    key_metadata: &KeyMetadata,
) -> Result<CredentialDefinition> {
    let protocol_data = match credential_metadata.additional_fields() {
        CoreProfilesMetadata::SDJWTVC(metadata) => Some(sd_jwt_protocol_data(metadata)),
        _ => None,
    };

    let proofs = supported_proofs(credential_metadata)?;

    let algs = match credential_metadata.additional_fields() {
        CoreProfilesMetadata::SDJWTVC(metadata) => sd_jwt_signing_algorithms(metadata)?,
        _ => None,
    };

    Ok(CredentialDefinition {
        cred_def_id: id.to_string(),
        format: credential_metadata.additional_fields().format(),
        claims: Default::default(),
        supported_proofs: proofs,
        supported_signing_algs: algs,
        display: None,
        protocol_data,
        key_metadata: key_metadata.to_owned(),
    })
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(),
)]
pub fn supported_proofs(
    credential_metadata: &oid4vci::metadata::CredentialMetadata<CoreProfilesMetadata>,
) -> Result<Option<HashMap<pop::Format, Vec<Alg>>>> {
    credential_metadata
        .proof_types_supported()
        .map(|proofs| {
            proofs
                .iter()
                .map(|(kpt, pt)| {
                    let fmt: pop::Format = kpt.into();
                    let algs = pt
                        .proof_signing_alg_values_supported
                        .iter()
                        .map(|s| Alg::from_str(s).context(CryptoSnafu))
                        .collect::<Result<Vec<Alg>>>();

                    algs.map(|vec| (fmt, vec))
                })
                .collect()
        })
        .transpose()
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
fn sd_jwt_protocol_data(metadata: &profiles::sd_jwt::Metadata) -> CredentialDefinitionData {
    let mut disclosures = vec![];

    for (k, v) in metadata.claims().unwrap_or(&HashMap::new()) {
        let parent_key = format!("$.{}", k.to_owned());
        disclosures.push(parent_key.clone());
        utils::serde::accumulate_claim_names(v.other(), parent_key, &mut disclosures);
    }

    CredentialDefinitionData::SdJwt {
        vct: metadata.vct().to_owned(),
        disclosures,
        lifetime: None,
    }
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(),
)]
fn sd_jwt_signing_algorithms(metadata: &profiles::sd_jwt::Metadata) -> Result<Option<Vec<Alg>>> {
    metadata
        .credential_signing_alg_values_supported()
        .map(|algs| {
            let res = algs
                .iter()
                .map(|s| s.try_into().context(CryptoSnafu))
                .collect::<Result<Vec<Alg>>>();
            res
        })
        .transpose()
}

impl From<&KeyProofType> for pop::Format {
    fn from(value: &KeyProofType) -> Self {
        match value {
            KeyProofType::Jwt => pop::Format::Jwt,
            KeyProofType::Cwt => pop::Format::Cwt,
        }
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
    fn format(&self) -> VCFormat {
        match self {
            CoreProfilesMetadata::SDJWTVC(_) => VCFormat::SdJwtVc,
            CoreProfilesMetadata::JWTVC(_) => VCFormat::JwtVcJson,
            CoreProfilesMetadata::JWTLDVC(_) => VCFormat::JwtVcJsonLD,
            CoreProfilesMetadata::LDVC(_) => VCFormat::LdpVc,
            CoreProfilesMetadata::ISOmDL(_) => VCFormat::MsoMdoc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inmem::kms::LocalKms;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vci::tests::fixtures::{AUTH_URL, CRED_DEF_ID, ISSUER_URL};
    use crate::vc::oid4vci::CredDefMetadata;
    use crate::vc::pop::Format;
    use serde_json::json;

    #[tokio::test]
    async fn converting_issuer_metadata_works() {
        let kms = LocalKms::new();
        let (_, default_key_metadata) = create_did_and_key_metadata(&kms).await;
        let (_, cred_def_key_metadata) = create_did_and_key_metadata(&kms).await;

        let metadata = sample_issuer_metadata();
        let cred_def_metadata = sample_credential_definition();
        let cred_defs =
            vec![cred_definition(CRED_DEF_ID, &cred_def_metadata, &cred_def_key_metadata).unwrap()];

        let expected = vc::core::IssuerMetadata {
            issuer_id: metadata.credential_issuer().to_string(),
            cred_defs,
            protocol_data: None,
        };

        let converted = convert_metadata(
            &metadata,
            &HashMap::from([(CRED_DEF_ID.to_owned(), cred_def_key_metadata)]),
            &default_key_metadata,
        )
        .unwrap();

        assert_eq!(converted, expected)
    }

    #[tokio::test]
    async fn converting_credential_metadata_works() {
        let kms = LocalKms::new();
        let cred_def_metadata = sample_credential_definition();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let mut expected = CredentialDefinition {
            cred_def_id: CRED_DEF_ID.to_owned(),
            format: cred_def_metadata.additional_fields().format(),
            claims: Default::default(),
            supported_proofs: supported_proofs(&cred_def_metadata).unwrap(),
            supported_signing_algs: Some(vec![Alg::ES256]),
            display: None,
            protocol_data: None,
            key_metadata: key_metadata.to_owned(),
        };

        expected.protocol_data = match cred_def_metadata.additional_fields() {
            CoreProfilesMetadata::SDJWTVC(metadata) => Some(sd_jwt_protocol_data(metadata)),
            _ => None,
        };

        let converted = cred_definition(CRED_DEF_ID, &cred_def_metadata, &key_metadata).unwrap();

        assert_eq!(converted, expected)
    }

    #[tokio::test]
    async fn cred_definition_returns_correct_data_with_none_in_specific_fields() {
        let kms = LocalKms::new();
        let cred_def_metadata = sample_credential_definition_without_scope();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let expected = CredentialDefinition {
            cred_def_id: "SD_JWT_cred_sample".to_string(),
            format: VCFormat::JwtVcJsonLD,
            claims: HashMap::new(),
            supported_proofs: None,
            supported_signing_algs: None,
            display: None,
            protocol_data: None,
            key_metadata: key_metadata.clone(),
        };

        let result = cred_definition(CRED_DEF_ID, &cred_def_metadata, &key_metadata).unwrap();
        assert_eq!(result, expected)
    }

    #[tokio::test]
    async fn retrieving_supported_proofs_works() {
        let kms = LocalKms::new();
        let cred_def_metadata = sample_credential_definition();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let expected = HashMap::from([(Format::Jwt, vec![Alg::ES256])]);

        let proofs = supported_proofs(&cred_def_metadata).unwrap().unwrap();

        assert_eq!(proofs, expected)
    }

    #[tokio::test]
    async fn converting_sd_jwt_protocol_data_works() {
        let cred_def_metadata = sample_credential_definition();
        let expected = CredentialDefinitionData::SdJwt {
            vct: "SD_JWT_cred".to_string(),
            disclosures: vec!["$.given_name".to_owned()],
            lifetime: None,
        };

        if let CoreProfilesMetadata::SDJWTVC(metadata) = cred_def_metadata.additional_fields() {
            let converted = sd_jwt_protocol_data(metadata);

            assert_eq!(converted, expected)
        };
    }

    fn sample_issuer_metadata() -> IssuerMetadata {
        let cred_def = serde_json::to_value(sample_credential_definition()).unwrap();
        let metadata = serde_json::from_value(json!(
            {
                "credential_issuer": ISSUER_URL,
                "authorization_servers": [AUTH_URL],
                "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                "credential_configurations_supported": {
                    CRED_DEF_ID: cred_def
                }
            }
        ));

        metadata.unwrap()
    }

    fn sample_credential_definition() -> CredDefMetadata {
        let cred_def = serde_json::from_value(json!({
            "format": "vc+sd-jwt",
            "scope": "SD_JWT_cred",
            "cryptographic_binding_methods_supported": [
                "jwk"
            ],
            "credential_signing_alg_values_supported": [
                "ES256"
            ],
            "proof_types_supported": {
                "jwt": {
                "proof_signing_alg_values_supported": [
                    "ES256"
                ]
                }
            },
            "vct": "SD_JWT_cred",
            "claims": {
                "given_name": {}
            }
        }));

        cred_def.unwrap()
    }

    fn sample_credential_definition_without_scope() -> CredDefMetadata {
        let cred_def = serde_json::from_value(json!({
            "format": "jwt_vc_json-ld",
            }
        ));

        cred_def.unwrap()
    }
}
