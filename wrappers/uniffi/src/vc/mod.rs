use crate::common::{Error, Result};
use agent_sdk::vc::HasVCFormat;
use uniffi::custom_type;
use uniffi::deps::anyhow;

pub mod oid4vci;
pub mod oid4vp;

pub type Alg = agent_sdk::crypto::Alg;
pub type VCFormat = agent_sdk::vc::VCFormat;
pub type Credential = agent_sdk::vc::Credential;
pub type CredentialMetadata = agent_sdk::vc::CredentialMetadata;
pub type VCStatus = agent_sdk::vc::VCStatus;
pub type TslVcStatus = agent_sdk::vc::TslVcStatus;

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum Alg {
    ES256,
    ES256K,
    EdDSA,
    BBS,
}

#[uniffi::remote(Enum)]
#[non_exhaustive]
enum VCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
    MsoMdoc,
}

#[derive(uniffi::Record)]
pub struct CredentialData {
    pub format: VCFormat,
    pub payload: String,
}

impl TryFrom<Credential> for CredentialData {
    type Error = Error;

    fn try_from(value: agent_sdk::vc::Credential) -> Result<Self> {
        let result = match value {
            Credential::JwtVcJson(payload) => Self {
                format: VCFormat::JwtVcJson,
                payload,
            },
            Credential::JwtVcJsonLd(payload) => Self {
                format: VCFormat::JwtVcJsonLD,
                payload,
            },
            Credential::LdpVc(payload) => Self {
                format: VCFormat::LdpVc,
                payload: serde_json::to_string(&payload)
                    .map_err(|e| Error::OID4VPHolder(e.to_string()))?,
            },
            Credential::SdJwt(payload) => Self {
                format: VCFormat::SdJwtVc,
                payload,
            },
            _ => {
                return Err(Error::OID4VCIInternal(format!(
                    "Unsupported credential format {}",
                    value.format()
                )));
            }
        };

        Ok(result)
    }
}

impl TryFrom<CredentialData> for Credential {
    type Error = Error;

    fn try_from(value: CredentialData) -> Result<Self> {
        let result = match value.format {
            VCFormat::JwtVcJson => Self::JwtVcJson(value.payload),
            VCFormat::JwtVcJsonLD => Self::JwtVcJsonLd(value.payload),
            VCFormat::LdpVc => Self::LdpVc(
                serde_json::from_str(&value.payload)
                    .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            ),
            VCFormat::SdJwtVc => Self::SdJwt(value.payload),
            VCFormat::MsoMdoc => {
                return Err(Error::OID4VPHolder(
                    "Unsupported credential format: MSO MDOC".to_string(),
                ));
            }
            _ => {
                return Err(Error::OID4VCIInternal(format!(
                    "Unsupported credential format {}",
                    value.format
                )));
            }
        };

        Ok(result)
    }
}

custom_type!(Credential, CredentialData, {
    remote,
    lower: |credential| credential.try_into().expect("unable serialize Credential"),
    try_lift: |credential_data| credential_data.try_into().map_err(anyhow::Error::msg),
});

#[uniffi::remote(Record)]
pub struct CredentialMetadata {
    pub type_: String,
    pub format: VCFormat,
    pub kid: String,
    pub alg: Option<Alg>,
    pub fields: Vec<String>,
}

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum TslVcStatus {
    Valid,
    Invalid,
    Suspended,
    AppSpecific(u8),
}

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum VCStatus {
    StatusListToken(TslVcStatus),
}
