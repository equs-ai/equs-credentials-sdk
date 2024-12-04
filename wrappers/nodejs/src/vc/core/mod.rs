mod holder;
mod issuer;
mod verifier;

use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::crypto::Alg;
use agent_sdk::vc::core::{
    CredentialDefinition, CredentialOffer, CredentialOfferContent, CredentialOfferData,
    CredentialRequest, CredentialRequestData, Display, HolderMetadata, IssuerMetadata,
    IssuerMetadataData, KeyMetadata, PresentationInput, PresentationRestriction, Proof,
};
use agent_sdk::vc::{Credential, CredentialMetadata, HasVCFormat, Presentation, VCFormat};
use napi::Error;
use napi_derive::napi;
use serde_json::{json, to_string, Value};

#[derive(Clone)]
#[napi(js_name = "KeyMetadata", object)]
pub struct JsKeyMetadata {
    pub did_url: String,
    pub kid: String,
}

impl From<JsKeyMetadata> for KeyMetadata {
    fn from(value: JsKeyMetadata) -> Self {
        KeyMetadata {
            did_url: value.did_url,
            kid: value.kid,
        }
    }
}

impl From<KeyMetadata> for JsKeyMetadata {
    fn from(value: KeyMetadata) -> Self {
        Self {
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
            _ => Err(Error::from_reason(format!(
                "Unsupported VC format: {value}"
            ))),
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
                .map(|(key, value)| Tag { key, value })
                .collect(),
        })
    }
}

#[napi(js_name = "Proof", object)]
pub struct JsProof {
    pub format: String,
    pub proof: String,
}

impl From<JsProof> for Proof {
    fn from(value: JsProof) -> Self {
        Self {
            format: value.format,
            proof: value.proof,
        }
    }
}

impl From<Proof> for JsProof {
    fn from(value: Proof) -> Self {
        Self {
            format: value.format,
            proof: value.proof,
        }
    }
}

#[napi(js_name = "CredentialRequestData", object)]
pub struct JsCredentialRequestData {
    pub proof_tolerance: Option<i64>,
}

impl From<JsCredentialRequestData> for CredentialRequestData {
    fn from(value: JsCredentialRequestData) -> Self {
        Self {
            proof_tolerance: value.proof_tolerance.map(time::Duration::seconds),
        }
    }
}

impl From<CredentialRequestData> for JsCredentialRequestData {
    fn from(value: CredentialRequestData) -> Self {
        Self {
            proof_tolerance: value.proof_tolerance.map(|d| d.whole_seconds()),
        }
    }
}

#[napi(js_name = "CredentialRequest", object)]
pub struct JsCredentialRequest {
    pub cred_def_id: String,
    pub cred_offer_id: Option<String>,
    pub proof: JsProof,
    pub protocol_data: Option<JsCredentialRequestData>,
}

impl From<JsCredentialRequest> for CredentialRequest {
    fn from(value: JsCredentialRequest) -> Self {
        let protocol_data = value.protocol_data.map(|value| value.into());
        Self {
            cred_def_id: value.cred_def_id,
            cred_offer_id: value.cred_offer_id,
            proof: value.proof.into(),
            protocol_data,
        }
    }
}

impl From<CredentialRequest> for JsCredentialRequest {
    fn from(value: CredentialRequest) -> Self {
        let protocol_data = value.protocol_data.map(|value| value.into());
        Self {
            cred_def_id: value.cred_def_id,
            cred_offer_id: value.cred_offer_id,
            proof: value.proof.into(),
            protocol_data,
        }
    }
}

#[napi(js_name = "CredentialOfferData", object)]
pub struct JsCredentialOfferData {}

impl From<JsCredentialOfferData> for CredentialOfferData {
    fn from(_value: JsCredentialOfferData) -> Self {
        Self {}
    }
}

impl From<CredentialOfferData> for JsCredentialOfferData {
    fn from(_value: CredentialOfferData) -> Self {
        Self {}
    }
}

#[napi(js_name = "CredentialOfferContentFormat")]
pub enum JsCredentialOfferContentFormat {
    CredDef,
    SupportedProofs,
}

#[napi(js_name = "CredentialOfferContent", object)]
pub struct JsCredentialOfferContent {
    pub format: JsCredentialOfferContentFormat,
    pub payload: JsonObject,
}

impl TryFrom<CredentialOfferContent> for JsCredentialOfferContent {
    type Error = Error;
    fn try_from(value: CredentialOfferContent) -> Result<Self, Error> {
        let result = match value {
            CredentialOfferContent::CredDef(value) => JsCredentialOfferContent {
                format: JsCredentialOfferContentFormat::CredDef,
                payload: to_json_object(value)?,
            },
            CredentialOfferContent::SupportedProofs(value) => JsCredentialOfferContent {
                format: JsCredentialOfferContentFormat::SupportedProofs,
                payload: serde_json::from_value(json!(value))?,
            },
        };
        Ok(result)
    }
}

impl TryFrom<JsCredentialOfferContent> for CredentialOfferContent {
    type Error = Error;

    fn try_from(value: JsCredentialOfferContent) -> Result<Self, Error> {
        let result = match value.format {
            JsCredentialOfferContentFormat::CredDef => {
                CredentialOfferContent::CredDef(from_json_object(value.payload)?)
            }
            JsCredentialOfferContentFormat::SupportedProofs => {
                CredentialOfferContent::SupportedProofs(serde_json::from_value(json!(
                    value.payload
                ))?)
            }
        };
        Ok(result)
    }
}

#[napi(js_name = "CredentialOffer", object)]
pub struct JsCredentialOffer {
    pub cred_offer_id: Option<String>,
    pub issuer_id: String,
    pub cred_def_id: String,
    pub content: JsCredentialOfferContent,
    pub protocol_data: Option<JsCredentialOfferData>,
}

impl TryFrom<JsCredentialOffer> for CredentialOffer {
    type Error = Error;
    fn try_from(value: JsCredentialOffer) -> Result<Self, Error> {
        let protocol_data = value.protocol_data.map(|value| value.into());
        Ok(Self {
            cred_offer_id: value.cred_offer_id,
            issuer_id: value.issuer_id,
            cred_def_id: value.cred_def_id,
            content: value.content.try_into()?,
            protocol_data,
        })
    }
}

impl TryFrom<CredentialOffer> for JsCredentialOffer {
    type Error = Error;
    fn try_from(value: CredentialOffer) -> Result<Self, Error> {
        let protocol_data = value.protocol_data.map(|value| value.into());
        Ok(Self {
            cred_offer_id: value.cred_offer_id,
            issuer_id: value.issuer_id,
            cred_def_id: value.cred_def_id,
            content: value.content.try_into()?,
            protocol_data,
        })
    }
}

#[napi(js_name = "PresentationRestriction", object)]
pub struct JsPresentationRestriction {
    pub fields: Vec<String>,
    pub value: Option<String>,
    pub optional: bool,
}

impl From<JsPresentationRestriction> for PresentationRestriction {
    fn from(value: JsPresentationRestriction) -> Self {
        Self {
            fields: value.fields,
            value: value.value,
            optional: value.optional,
        }
    }
}

impl From<PresentationRestriction> for JsPresentationRestriction {
    fn from(value: PresentationRestriction) -> Self {
        Self {
            fields: value.fields,
            value: value.value,
            optional: value.optional,
        }
    }
}

#[napi(js_name = "PresentationInput", object)]
pub struct JsPresentationInput {
    pub id: String,
    pub format: Option<Value>,
    pub restrictions: Vec<JsPresentationRestriction>,
}

impl TryFrom<JsPresentationInput> for PresentationInput {
    type Error = Error;

    fn try_from(value: JsPresentationInput) -> Result<Self, Error> {
        Ok(Self {
            id: value.id,
            format: value.format.map(serde_json::from_value).transpose()?,
            restrictions: value.restrictions.into_iter().map(|v| v.into()).collect(),
        })
    }
}

impl TryFrom<PresentationInput> for JsPresentationInput {
    type Error = Error;

    fn try_from(value: PresentationInput) -> Result<Self, Error> {
        Ok(Self {
            id: value.id,
            format: value.format.map(serde_json::to_value).transpose()?,
            restrictions: value.restrictions.into_iter().map(|v| v.into()).collect(),
        })
    }
}

#[allow(clippy::enum_variant_names)]
#[napi(js_name = "PresentationFormat")]
pub enum JsPresentationFormat {
    JwtVp,
    LdpVp,
    SdJwtVp,
}

#[napi(js_name = "Presentation", object)]
pub struct JsPresentation {
    pub format: JsPresentationFormat,
    pub payload: String,
}

impl TryFrom<JsPresentation> for Presentation {
    type Error = Error;
    fn try_from(value: JsPresentation) -> Result<Self, Error> {
        let result = match value.format {
            JsPresentationFormat::JwtVp => {
                Presentation::JwtVp(serde_json::from_str(&value.payload)?)
            }
            JsPresentationFormat::LdpVp => {
                Presentation::LdpVp(serde_json::from_str(&value.payload)?)
            }
            JsPresentationFormat::SdJwtVp => Presentation::SdJwtVp(value.payload),
        };
        Ok(result)
    }
}

impl TryFrom<Presentation> for JsPresentation {
    type Error = Error;
    fn try_from(value: Presentation) -> Result<Self, Error> {
        match value {
            Presentation::JwtVp(value) => Ok(Self {
                format: JsPresentationFormat::JwtVp,
                payload: to_string(&value)?,
            }),
            Presentation::LdpVp(value) => Ok(Self {
                format: JsPresentationFormat::LdpVp,
                payload: to_string(&value)?,
            }),
            Presentation::SdJwtVp(value) => Ok(Self {
                format: JsPresentationFormat::SdJwtVp,
                payload: value,
            }),
            _ => Err(Error::from_reason(format!(
                "Unsupported presentation format: {:?}",
                value
            ))),
        }
    }
}

#[napi(js_name = "IssuerMetadataData", object)]
pub struct JsIssuerMetadataData {}

impl From<IssuerMetadataData> for JsIssuerMetadataData {
    fn from(_value: IssuerMetadataData) -> Self {
        Self {}
    }
}

impl From<JsIssuerMetadataData> for IssuerMetadataData {
    fn from(_value: JsIssuerMetadataData) -> Self {
        Self {}
    }
}

#[napi(js_name = "Display", object)]
pub struct JsDisplay {}

impl From<Display> for JsDisplay {
    fn from(_value: Display) -> Self {
        Self {}
    }
}

impl From<JsDisplay> for Display {
    fn from(_value: JsDisplay) -> Self {
        Self {}
    }
}

#[napi(js_name = "CredentialDefinition", object)]
pub struct JsCredentialDefinition {
    pub cred_def_id: String,
    pub format: JsVCFormat,
    pub claims: JsonObject,
    pub supported_proofs: Option<JsonObject>,
    pub supported_signing_algs: Option<Vec<JsAlg>>,
    pub display: Option<JsDisplay>,
    pub protocol_data: Option<JsonObject>,
    pub key_metadata: JsKeyMetadata,
}

impl TryFrom<CredentialDefinition> for JsCredentialDefinition {
    type Error = Error;
    fn try_from(value: CredentialDefinition) -> Result<Self, Error> {
        let supported_proofs = value.supported_proofs.map(to_json_object).transpose()?;
        let mut supported_signing_algs: Vec<JsAlg> = vec![];
        if let Some(v) = value.supported_signing_algs {
            for alg in v {
                let js_alg = alg.try_into()?;
                supported_signing_algs.push(js_alg);
            }
        };
        Ok(Self {
            cred_def_id: value.cred_def_id,
            format: value.format.try_into()?,
            claims: to_json_object(value.claims)?,
            supported_proofs,
            supported_signing_algs: Some(supported_signing_algs),
            display: value.display.map(|v| v.into()),
            protocol_data: Some(to_json_object(value.protocol_data)?),
            key_metadata: value.key_metadata.into(),
        })
    }
}

impl TryFrom<JsCredentialDefinition> for CredentialDefinition {
    type Error = Error;
    fn try_from(value: JsCredentialDefinition) -> Result<Self, Error> {
        let supported_proofs = value.supported_proofs.map(from_json_object).transpose()?;
        let mut supported_signing_algs: Vec<Alg> = vec![];
        if let Some(v) = value.supported_signing_algs {
            for alg in v {
                let js_alg: Alg = alg.into();
                supported_signing_algs.push(js_alg);
            }
        };
        Ok(Self {
            cred_def_id: value.cred_def_id,
            format: value.format.into(),
            claims: from_json_object(value.claims)?,
            supported_proofs,
            supported_signing_algs: Some(supported_signing_algs),
            display: value.display.map(|v| v.into()),
            protocol_data: value.protocol_data.map(from_json_object).transpose()?,
            key_metadata: value.key_metadata.into(),
        })
    }
}

#[napi(object, js_name = "IssuerMetadata")]
pub struct JsIssuerMetadata {
    pub issuer_id: String,
    pub cred_defs: Vec<JsCredentialDefinition>,
    pub protocol_data: Option<JsIssuerMetadataData>,
}

#[napi]
impl TryFrom<JsIssuerMetadata> for IssuerMetadata {
    type Error = Error;
    fn try_from(value: JsIssuerMetadata) -> Result<Self, Error> {
        Ok(Self {
            issuer_id: value.issuer_id,
            cred_defs: value
                .cred_defs
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<Vec<CredentialDefinition>, Error>>()?,
            protocol_data: value.protocol_data.map(|v| v.into()),
        })
    }
}

#[napi]
impl TryFrom<IssuerMetadata> for JsIssuerMetadata {
    type Error = Error;
    fn try_from(value: IssuerMetadata) -> Result<Self, Error> {
        Ok(Self {
            issuer_id: value.issuer_id,
            cred_defs: value
                .cred_defs
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<Vec<JsCredentialDefinition>, Error>>()?,
            protocol_data: value.protocol_data.map(|v| v.into()),
        })
    }
}

#[napi(js_name = "HolderMetadata", object)]
pub struct JsHolderMetadata {
    pub client_id: String,
}

#[napi]
impl From<JsHolderMetadata> for HolderMetadata {
    fn from(value: JsHolderMetadata) -> Self {
        Self {
            client_id: value.client_id,
        }
    }
}

#[napi]
impl From<HolderMetadata> for JsHolderMetadata {
    fn from(value: HolderMetadata) -> Self {
        Self {
            client_id: value.client_id,
        }
    }
}
