use crate::crypto::Alg;
use crate::vc::core::{CredentialDefinition, CredentialDefinitionData, KeyMetadata};
use crate::vc::{pop, HasVCFormat, VCFormat};
use crate::{crypto, vc};
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

#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Crypto error at {location}"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
}

type Result<T> = std::result::Result<T, Error>;

#[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE),
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
        ret(level = Level::TRACE),
)]
pub fn cred_definition(
    id: &String,
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

fn sd_jwt_protocol_data(metadata: &profiles::sd_jwt::Metadata) -> CredentialDefinitionData {
    let disclosures = metadata
        .credential_definition()
        .claims()
        .unwrap_or(&HashMap::new())
        .keys()
        .map(|k| format!("$.{}", k.to_owned()))
        .collect();

    CredentialDefinitionData::SdJwt {
        vct: metadata.vct().to_owned(),
        disclosures,
        lifetime: None,
    }
}

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
