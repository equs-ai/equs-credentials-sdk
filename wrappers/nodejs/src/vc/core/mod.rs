use agent_sdk::crypto::Alg;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::{Credential, CredentialMetadata, HasVCFormat, VCFormat};
use napi::Error;
use napi_derive::napi;

#[derive(Clone)]
#[napi(js_name = "KeyMetadata", object)]
pub struct JsKeyMetadata {
    pub did_url: String,
    pub kid: String,
}
#[derive(Clone)]
#[napi(js_name = "DIDAndKeyMetadata", object)]
pub struct JsDIDAndKeyMetadata {
    pub key_metadata: JsKeyMetadata,
    pub did: String,
}

impl From<JsKeyMetadata> for KeyMetadata {
    fn from(value: JsKeyMetadata) -> Self {
        KeyMetadata {
            did_url: value.did_url,
            kid: value.kid,
        }
    }
}

#[napi(js_name = "VCFormat")]
pub enum JsVCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
    MsoMdoc,
}

impl From<JsVCFormat> for VCFormat {
    fn from(value: JsVCFormat) -> Self {
        match value {
            JsVCFormat::JwtVcJson => VCFormat::JwtVcJson,
            JsVCFormat::JwtVcJsonLD => VCFormat::JwtVcJsonLD,
            JsVCFormat::LdpVc => VCFormat::LdpVc,
            JsVCFormat::SdJwtVc => VCFormat::SdJwtVc,
            JsVCFormat::MsoMdoc => VCFormat::MsoMdoc,
        }
    }
}

impl TryFrom<VCFormat> for JsVCFormat {
    type Error = Error;

    fn try_from(value: VCFormat) -> napi::Result<Self> {
        match value {
            VCFormat::JwtVcJson => Ok(JsVCFormat::JwtVcJson),
            VCFormat::JwtVcJsonLD => Ok(JsVCFormat::JwtVcJsonLD),
            VCFormat::LdpVc => Ok(JsVCFormat::LdpVc),
            VCFormat::SdJwtVc => Ok(JsVCFormat::SdJwtVc),
            VCFormat::MsoMdoc => Ok(JsVCFormat::MsoMdoc),
            _ => Err(Error::from_reason(format!("Format not supported {value}"))),
        }
    }
}

#[napi(js_name = "Alg")]
pub enum JsAlg {
    ES256,
    EdDSA,
}

impl From<JsAlg> for Alg {
    fn from(value: JsAlg) -> Self {
        match value {
            JsAlg::ES256 => Alg::ES256,
            JsAlg::EdDSA => Alg::EdDSA,
        }
    }
}

impl TryFrom<Alg> for JsAlg {
    type Error = Error;

    fn try_from(value: Alg) -> napi::Result<Self> {
        let alg = match value {
            Alg::ES256 => JsAlg::ES256,
            Alg::EdDSA => JsAlg::EdDSA,
            _ => {
                return Err(Error::from_reason(format!(
                    "Unsupported algorithm: {value}"
                )))
            }
        };

        Ok(alg)
    }
}

#[derive(Clone)]
#[napi(js_name = "Credential", object)]
pub struct JsCredential {
    pub format: JsVCFormat,
    pub payload: String,
}

impl TryFrom<Credential> for JsCredential {
    type Error = Error;

    fn try_from(value: Credential) -> napi::Result<Self> {
        let result = match value {
            Credential::JwtVcJson(payload) => Self {
                format: JsVCFormat::JwtVcJson,
                payload,
            },
            Credential::JwtVcJsonLd(payload) => Self {
                format: JsVCFormat::JwtVcJsonLD,
                payload,
            },
            Credential::LdpVc(payload) => Self {
                format: JsVCFormat::LdpVc,
                payload: serde_json::to_string(&payload)?,
            },
            Credential::SdJwt(payload) => Self {
                format: JsVCFormat::SdJwtVc,
                payload,
            },
            _ => {
                return Err(Error::from_reason(format!(
                    "Unsupported credential format {}",
                    value.format()
                )))
            }
        };

        Ok(result)
    }
}

impl TryFrom<JsCredential> for Credential {
    type Error = Error;

    fn try_from(value: JsCredential) -> napi::Result<Self> {
        let result = match value.format {
            JsVCFormat::JwtVcJson => Self::JwtVcJson(value.payload),
            JsVCFormat::JwtVcJsonLD => Self::JwtVcJsonLd(value.payload),
            JsVCFormat::LdpVc => Self::LdpVc(serde_json::from_str(&value.payload)?),
            JsVCFormat::SdJwtVc => Self::SdJwt(value.payload),
            JsVCFormat::MsoMdoc => {
                return Err(Error::from_reason(
                    "Unsupported credential format: MSO MDOC",
                ))
            }
        };

        Ok(result)
    }
}

#[napi(object)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

#[napi(js_name = "CredentialMetadata", object)]
pub struct JsCredentialMetadata {
    pub type_: String,
    pub format: JsVCFormat,
    pub kid: String,
    pub alg: Option<JsAlg>,
    pub tags: Vec<Tag>,
}

impl From<JsCredentialMetadata> for CredentialMetadata {
    fn from(value: JsCredentialMetadata) -> Self {
        Self {
            type_: value.type_,
            format: value.format.into(),
            kid: value.kid,
            alg: value.alg.map(|value| value.into()),
            tags: value
                .tags
                .into_iter()
                .map(|tag| (tag.key, tag.value))
                .collect(),
        }
    }
}

impl TryFrom<CredentialMetadata> for JsCredentialMetadata {
    type Error = Error;
    fn try_from(value: CredentialMetadata) -> napi::Result<Self> {
        Ok(Self {
            type_: value.type_,
            format: value.format.try_into()?,
            kid: value.kid,
            alg: value.alg.map(|value| value.try_into()).transpose()?,
            tags: value
                .tags
                .into_iter()
                .map(|tag| Tag {
                    key: tag.0,
                    value: tag.1,
                })
                .collect(),
        })
    }
}
