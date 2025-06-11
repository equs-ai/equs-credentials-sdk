use crate::crypto::{Alg, AlgNotSupportedSnafu};
use crate::vc::core::{CredentialDefinition, CredentialDefinitionData, KeyMetadata};
use crate::vc::{HasVCFormat, VCFormat, pop};
use crate::{crypto, utils, vc};
use common_macros::DebugError;
use oid4vci::core::profiles::{
    CoreProfilesCredentialConfiguration, CoreProfilesCredentialResponseType,
};
use oid4vci::metadata::credential_issuer::CredentialConfiguration;
use oid4vci::proof_of_possession::KeyProofType;
use oid4vci::types::CredentialConfigurationId;
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::str::FromStr;
use time::Duration;
use tracing::{Level, instrument, trace};

pub type IssuerMetadata = oid4vci::core::metadata::CredentialIssuerMetadata;
pub type CredentialMetadata = CredentialConfiguration<CoreProfilesCredentialConfiguration>;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Crypto error"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
    #[snafu(display("Unsupported credential request"))]
    UnsupportedCredentialRequest {
        #[snafu(implicit)]
        location: Location,
    },
}

type Result<T> = std::result::Result<T, Error>;

#[instrument(level = Level::TRACE, err(), ret())]
pub fn convert_metadata(
    issuer_metadata: &IssuerMetadata,
    cred_def_ids_with_key_metadata: &HashMap<String, KeyMetadata>,
    default_key_metadata: &KeyMetadata,
    default_cred_lifetime: Duration,
    cred_lifetime_per_cred_conf_id: HashMap<CredentialConfigurationId, Duration>,
) -> Result<vc::core::IssuerMetadata> {
    let cred_defs = issuer_metadata
        .credential_configurations_supported()
        .iter()
        .map(|cc| {
            let cred_lifetime = cred_lifetime_per_cred_conf_id
                .get(cc.id())
                .unwrap_or(&default_cred_lifetime);
            cred_definition(
                cc.id(),
                cc,
                cred_def_ids_with_key_metadata
                    .get(cc.id().as_str())
                    .unwrap_or(default_key_metadata),
                cred_lifetime.to_owned(),
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

#[instrument(level = Level::TRACE, err(), ret())]
pub fn cred_definition(
    id: &str,
    credential_metadata: &CredentialMetadata,
    key_metadata: &KeyMetadata,
    cred_lifetime: Duration,
) -> Result<CredentialDefinition> {
    let protocol_data = match credential_metadata.profile_specific_fields() {
        CoreProfilesCredentialConfiguration::VcSdJwt(metadata) => {
            Some(sd_jwt_protocol_data(metadata, cred_lifetime))
        }
        CoreProfilesCredentialConfiguration::LdpVc(metadata) => {
            Some(json_ld_protocol_data(metadata, cred_lifetime))
        }
        _ => None,
    };

    let proofs = supported_proofs(credential_metadata)?;

    let algs = match credential_metadata.profile_specific_fields() {
        CoreProfilesCredentialConfiguration::VcSdJwt(metadata) => {
            Some(sd_jwt_signing_algorithms(metadata)?)
        }
        CoreProfilesCredentialConfiguration::JwtVcJsonLd(metadata) => {
            Some(json_ld_signing_algorithms(metadata)?)
        }
        _ => None,
    };

    Ok(CredentialDefinition {
        cred_def_id: id.to_string(),
        format: credential_metadata.profile_specific_fields().format(),
        claims: Default::default(),
        supported_proofs: proofs,
        supported_signing_algs: algs,
        display: None,
        protocol_data,
        key_metadata: key_metadata.to_owned(),
    })
}

#[instrument(level = Level::TRACE, err(), ret())]
pub fn supported_proofs(
    credential_metadata: &CredentialMetadata,
) -> Result<Option<HashMap<pop::Format, Vec<Alg>>>> {
    credential_metadata
        .proof_types_supported()
        .map(|proofs| {
            proofs
                .iter()
                .map(|key_proof_type_supported| {
                    let fmt: pop::Format = match key_proof_type_supported.to_owned().key {
                        KeyProofType::Jwt => pop::Format::Jwt,
                        KeyProofType::LdpVp => pop::Format::Ldp,
                    };
                    let algs = key_proof_type_supported
                        .proof_signing_alg_values_supported
                        .iter()
                        .map(|alg| Alg::from_str(alg.as_ref()).context(CryptoSnafu))
                        .collect::<Result<Vec<Alg>>>();

                    algs.map(|vec| (fmt, vec))
                })
                .collect()
        })
        .transpose()
}

#[instrument(level = Level::TRACE, ret())]
fn sd_jwt_protocol_data(
    metadata: &oid4vci::core::profiles::vc_sd_jwt::CredentialConfiguration,
    cred_lifetime: Duration,
) -> CredentialDefinitionData {
    let mut disclosures = vec![];

    for (k, v) in metadata.claims().unwrap_or(&HashMap::new()) {
        let parent_key = format!("$.{}", k.to_owned());
        disclosures.push(parent_key.clone());
        let json = serde_json::to_value(v.deref().to_owned()).unwrap_or(serde_json::Value::Null);
        utils::serde::accumulate_claim_names(&json, parent_key, &mut disclosures);
    }

    CredentialDefinitionData::SdJwt {
        vct: metadata.vct().to_owned(),
        disclosures,
        lifetime: cred_lifetime,
    }
}

#[instrument(level = Level::TRACE, ret())]
fn json_ld_protocol_data(
    metadata: &oid4vci::core::profiles::ldp_vc::CredentialConfiguration,
    cred_lifetime: Duration,
) -> CredentialDefinitionData {
    let contexts = metadata
        .credential_definition()
        .context()
        .iter()
        .map(|ctx| ctx.as_str().unwrap_or_default().to_string())
        .collect();

    let vc_types = metadata.credential_definition().r#type().clone();

    CredentialDefinitionData::Ldp {
        contexts,
        vc_types,
        credential_id: None,
        lifetime: cred_lifetime,
    }
}

#[instrument(level = Level::TRACE, err(), ret())]
fn sd_jwt_signing_algorithms(
    metadata: &oid4vci::core::profiles::vc_sd_jwt::CredentialConfiguration,
) -> Result<Vec<Alg>> {
    metadata
        .credential_signing_alg_values_supported()
        .iter()
        .map(|alg| alg.try_into().context(CryptoSnafu))
        .collect()
}

#[instrument(level = Level::TRACE, err(), ret())]
fn json_ld_signing_algorithms(
    metadata: &oid4vci::core::profiles::jwt_vc_json_ld::CredentialConfiguration,
) -> Result<Vec<Alg>> {
    let mut algs = vec![];
    for crypto_suites in metadata.credential_signing_alg_values_supported() {
        let alg = match crypto_suites.as_str() {
            "Ed25519Signature2018" | "Ed25519Signature2020" => Ok(Alg::EdDSA),
            "EcdsaSecp256r1Signature2019" => Ok(Alg::ES256),
            "EcdsaSecp256k1Signature2019" => Ok(Alg::ES256K),
            _ => Err(AlgNotSupportedSnafu {
                alg: crypto_suites.to_string(),
            }
            .build()),
        }
        .context(CryptoSnafu)?;

        algs.push(alg)
    }

    Ok(algs)
}

impl From<&KeyProofType> for pop::Format {
    fn from(value: &KeyProofType) -> Self {
        match value {
            KeyProofType::Jwt => pop::Format::Jwt,
            KeyProofType::LdpVp => pop::Format::Ldp,
        }
    }
}

impl HasVCFormat for CoreProfilesCredentialResponseType {
    fn format(&self) -> VCFormat {
        match self {
            CoreProfilesCredentialResponseType::JwtVcJson { .. } => VCFormat::JwtVcJson,
            CoreProfilesCredentialResponseType::JwtVcJsonLd { .. } => VCFormat::JwtVcJsonLD,
            CoreProfilesCredentialResponseType::LdpVc { .. } => VCFormat::LdpVc,
            CoreProfilesCredentialResponseType::MsoMdoc { .. } => VCFormat::MsoMdoc,
            CoreProfilesCredentialResponseType::VcSdJwt { .. } => VCFormat::SdJwtVc,
        }
    }
}

impl HasVCFormat for CoreProfilesCredentialConfiguration {
    fn format(&self) -> VCFormat {
        match self {
            CoreProfilesCredentialConfiguration::VcSdJwt(_) => VCFormat::SdJwtVc,
            CoreProfilesCredentialConfiguration::JwtVcJson(_) => VCFormat::JwtVcJson,
            CoreProfilesCredentialConfiguration::JwtVcJsonLd(_) => VCFormat::JwtVcJsonLD,
            CoreProfilesCredentialConfiguration::LdpVc(_) => VCFormat::LdpVc,
            CoreProfilesCredentialConfiguration::MsoMdoc(_) => VCFormat::MsoMdoc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inmem::kms::LocalKms;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vci::CredDefMetadata;
    use crate::vc::oid4vci::tests::fixtures::{AUTH_URL, CRED_DEF_ID, ISSUER_URL};
    use crate::vc::pop::Format;
    use serde_json::json;

    #[tokio::test]
    async fn converting_issuer_metadata_works() {
        let kms = LocalKms::new();
        let (_, default_key_metadata) = create_did_and_key_metadata(&kms).await;
        let (_, cred_def_key_metadata) = create_did_and_key_metadata(&kms).await;

        let metadata = sample_issuer_metadata();
        let cred_def_metadata = sample_credential_definition();
        let cred_defs = vec![
            cred_definition(
                CRED_DEF_ID,
                &cred_def_metadata,
                &cred_def_key_metadata,
                Duration::days(5 * 365),
            )
            .unwrap(),
        ];

        let expected = vc::core::IssuerMetadata {
            issuer_id: metadata.credential_issuer().to_string(),
            cred_defs,
            protocol_data: None,
        };

        let converted = convert_metadata(
            &metadata,
            &HashMap::from([(CRED_DEF_ID.to_owned(), cred_def_key_metadata)]),
            &default_key_metadata,
            Duration::days(5 * 365),
            Default::default(),
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
            format: cred_def_metadata.profile_specific_fields().format(),
            claims: Default::default(),
            supported_proofs: supported_proofs(&cred_def_metadata).unwrap(),
            supported_signing_algs: Some(vec![Alg::ES256]),
            display: None,
            protocol_data: None,
            key_metadata: key_metadata.to_owned(),
        };

        expected.protocol_data = match cred_def_metadata.profile_specific_fields() {
            CoreProfilesCredentialConfiguration::VcSdJwt(metadata) => {
                Some(sd_jwt_protocol_data(metadata, Duration::days(5 * 365)))
            }
            _ => None,
        };

        let converted = cred_definition(
            CRED_DEF_ID,
            &cred_def_metadata,
            &key_metadata,
            Duration::days(5 * 365),
        )
        .unwrap();

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
            supported_signing_algs: Some(vec![]),
            display: None,
            protocol_data: None,
            key_metadata: key_metadata.clone(),
        };

        let result = cred_definition(
            CRED_DEF_ID,
            &cred_def_metadata,
            &key_metadata,
            Duration::days(5 * 365),
        )
        .unwrap();
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
            lifetime: Duration::days(5 * 365),
        };

        if let CoreProfilesCredentialConfiguration::VcSdJwt(metadata) =
            cred_def_metadata.profile_specific_fields()
        {
            let converted = sd_jwt_protocol_data(metadata, Duration::days(5 * 365));

            assert_eq!(converted, expected)
        };
    }

    fn sample_issuer_metadata() -> IssuerMetadata {
        let serde_json::Value::Object(mut cred_def) =
            serde_json::to_value(sample_credential_definition()).unwrap()
        else {
            panic!("credential definition should be an object");
        };
        cred_def.remove("$key$");

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
            "$key$": CRED_DEF_ID,
            "format": "dc+sd-jwt",
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
            "$key$": "sample_jwt_vc_credential_definition",
            "format": "jwt_vc_json-ld",
            "credential_definition": {
                "@context": [],
                "type": [],
                "credential_subject": {},
            },
        }));

        cred_def.unwrap()
    }
}
