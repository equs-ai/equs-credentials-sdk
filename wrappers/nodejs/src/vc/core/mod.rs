mod error;
mod holder;
mod issuer;
mod status_issuer;
mod verifier;

use crate::utils::{from_json_object, to_json_object};

use crate::vc::JsonObject;
use agent_sdk::chrono_time_mapping::{TryIntoChrono, TryIntoTime};
use agent_sdk::crypto::Alg;
use agent_sdk::vc::core::{
    CredentialDefinition, CredentialOffer, CredentialOfferContent, CredentialOfferData,
    CredentialRequest, CredentialRequestData, CredentialStatusInfo, DEFAULT_POP_LIFETIME_MINUTES,
    Display, HolderBinder, HolderMetadata, IssuerMetadata, IssuerMetadataData, KeyMetadata,
    PresentationInput, PresentationRestriction, Proof, ProofOfPossessionMetadata,
    ProofOfPossessionNotBefore,
};
use agent_sdk::vc::core::{CredentialDefinitionData, PresentationRestrictionValue};
use chrono::{DateTime, Utc};

use agent_sdk::vc::VCStatus;
use agent_sdk::vc::core::StatusIssuerMetadata;
use agent_sdk::vc::core::StatusListDefinition;
use agent_sdk::vc::status_formats::status_list_token_jwt;
use agent_sdk::vc::{StatusList, VCStatusesData};

use crate::vc::status_formats::{JsStatusListFormat, TslVcStatusType};
use agent_sdk::nonce::Nonce;
use agent_sdk::vc::{Credential, CredentialMetadata, HasVCFormat, Presentation, VCFormat};
use napi::Error;
use napi_derive::napi;
use serde_json::{json, to_string};
use time::Duration;
use time::error::ComponentRange;

/// A helper interface for handling Keys and `DID`s for the services.
///
/// @property {string} didUrl - `DID` url of the party
/// @property {string} kid - corresponding key ID to access the key
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
    ES256K,
    EdDSA,
}

impl From<JsAlg> for Alg {
    fn from(value: JsAlg) -> Self {
        match value {
            JsAlg::ES256 => Alg::ES256,
            JsAlg::ES256K => Alg::ES256K,
            JsAlg::EdDSA => Alg::EdDSA,
        }
    }
}

impl TryFrom<Alg> for JsAlg {
    type Error = Error;

    fn try_from(value: Alg) -> napi::Result<Self> {
        let alg = match value {
            Alg::ES256 => JsAlg::ES256,
            Alg::ES256K => JsAlg::ES256K,
            Alg::EdDSA => JsAlg::EdDSA,
            _ => {
                return Err(Error::from_reason(format!(
                    "Unsupported algorithm: {value}"
                )));
            }
        };

        Ok(alg)
    }
}

/// Verifiable Credential (`VC`)
///
/// @property {VCFormat} format - format of `VC`
/// @property {string} payload - `VC` in a string representation
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
                )));
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
                ));
            }
        };

        Ok(result)
    }
}

/// `Credential Metadata`
///
/// Contains the various data related to some {@link Credential}.
///
/// @property {string} type - type of {@link Credential}
/// @property {VCFormat} format - format of {@link Credential}
/// @property {string} kid - The Key ID representing the ID of the cryptographic key used to sign the presentation of a credential.
/// @property {Alg} [alg] - Algorithm of {@link Credential}
/// @property {Array<string>} fields - Fields to filter by
#[napi(js_name = "CredentialMetadata", object)]
pub struct JsCredentialMetadata {
    pub type_: String,
    pub format: JsVCFormat,
    pub kid: String,
    pub alg: Option<JsAlg>,
    pub fields: Vec<String>,
}

impl From<JsCredentialMetadata> for CredentialMetadata {
    fn from(value: JsCredentialMetadata) -> Self {
        Self {
            type_: value.type_,
            format: value.format.into(),
            kid: value.kid,
            alg: value.alg.map(|value| value.into()),
            fields: value.fields,
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
            fields: value.fields,
        })
    }
}

/// An interface for handling Proof of Possession.
///
/// @property {string} format - Format of `proof`
/// @property {string} proof - Value of `proof`
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

/// A protocol-specific data for the {@link CredentialRequest}.
///
/// @property {number} [proofTolerance] - Duration of proof (in seconds)
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

/// A `CredentialRequest` entity.
///
/// Contains the data related to requested {@link Credential}.
///
/// Built by `Holder` to be propagated later to the `Issuer` in exchange for actual {@link Credential}.
///
/// @property {string} credDefId - ID of credential definition
/// @property {string} [credOfferId] - ID of credential offer
/// @property {Proof} proof - proof of possession (MANDATORY)
/// @property {CredentialRequestData} [protocolData] - credential request data
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

/// A protocol-specific data for the {@link CredentialOffer}
///
/// *NOTE*: will be extended in the next releases.
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

/// An enum that defines the different formats of representations for credential definition.
///
/// # Variants:
///
/// * `SdJwt` - Indicates that the credential is in SD JWT format.
/// * `Ldp` - Indicates that the credential is in LD Json format.
#[napi(js_name = "CredentialDefinitionFormat")]
pub enum JsCredentialDefinitionDataFormat {
    SdJwt,
    Ldp,
}

/// Credential Definition Data
///
/// @property {CredentialDefinitionDataFormat} format - format of `Credential`
/// @property {JsonObject} payload - payload of `Credential format related params`
#[napi(js_name = "CredentialDefinitionData", object)]
pub struct JsCredentialDefinitionData {
    pub format: JsCredentialDefinitionDataFormat,
    pub payload: JsonObject,
}

impl TryFrom<CredentialDefinitionData> for JsCredentialDefinitionData {
    type Error = Error;
    fn try_from(value: CredentialDefinitionData) -> Result<Self, Error> {
        let result = match value {
            CredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime,
            } => JsCredentialDefinitionData {
                format: JsCredentialDefinitionDataFormat::SdJwt,
                payload: to_json_object(
                    json!({ "vct": vct, "disclosures": disclosures, "lifetime": lifetime.whole_milliseconds() }),
                )?,
            },
            CredentialDefinitionData::Ldp {
                contexts,
                vc_types,
                credential_id,
                lifetime,
            } => JsCredentialDefinitionData {
                format: JsCredentialDefinitionDataFormat::Ldp,
                payload: to_json_object(
                    json!({"contexts": contexts, "vc_types": vc_types, "credential_id": credential_id.unwrap_or("".to_string()), "lifetime": lifetime.whole_milliseconds() }),
                )?,
            },
            _ => {
                return Err(Error::from_reason(
                    "Cannot convert CredentialDefinitionData to JsCredentialDefinitionData",
                ));
            }
        };
        Ok(result)
    }
}
impl TryFrom<JsCredentialDefinitionData> for CredentialDefinitionData {
    type Error = Error;
    fn try_from(value: JsCredentialDefinitionData) -> Result<Self, Error> {
        let result = match value.format {
            JsCredentialDefinitionDataFormat::SdJwt => {
                let vct: String = value
                    .payload
                    .get("vct")
                    .ok_or_else(|| napi::Error::from_reason("'vct' must be in payload"))?
                    .as_str()
                    .ok_or_else(|| napi::Error::from_reason("'vct' must be a String"))?
                    .into();
                let disclosures: Vec<String> = value
                    .payload
                    .get("disclosures")
                    .ok_or_else(|| napi::Error::from_reason("'disclosures' must be in payload"))?
                    .as_array()
                    .ok_or_else(|| napi::Error::from_reason("'disclosures' must be an array"))?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .ok_or_else(|| {
                                Error::from_reason("Couldnt convert value disclosure to str")
                            })
                            .unwrap()
                            .to_string()
                    })
                    .collect();
                let lifetime: i64 = value
                    .payload
                    .get("lifetime")
                    .ok_or_else(|| napi::Error::from_reason("'lifetime' must be in payload"))?
                    .as_i64()
                    .ok_or_else(|| napi::Error::from_reason("'lifetime' must be a i64"))?;
                let lifetime = Duration::milliseconds(lifetime);

                CredentialDefinitionData::SdJwt {
                    vct,
                    disclosures,
                    lifetime,
                }
            }
            JsCredentialDefinitionDataFormat::Ldp => {
                let contexts: Vec<String> = value
                    .payload
                    .get("contexts")
                    .ok_or_else(|| napi::Error::from_reason("'contexts' must be in payload"))?
                    .as_array()
                    .ok_or_else(|| napi::Error::from_reason("'contexts' must be an array"))?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .ok_or_else(|| {
                                Error::from_reason("Couldnt convert value contexts to str")
                            })
                            .unwrap()
                            .to_string()
                    })
                    .collect();
                let lifetime: i64 = value
                    .payload
                    .get("lifetime")
                    .ok_or_else(|| napi::Error::from_reason("'lifetime' must be in payload"))?
                    .as_i64()
                    .ok_or_else(|| napi::Error::from_reason("'lifetime' must be a i64"))?;
                let lifetime = Duration::milliseconds(lifetime);

                let vc_types: Vec<String> = value
                    .payload
                    .get("vc_types")
                    .ok_or_else(|| napi::Error::from_reason("'vc_types' must be in payload"))?
                    .as_array()
                    .ok_or_else(|| napi::Error::from_reason("'vc_types' must be an array"))?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .ok_or_else(|| {
                                Error::from_reason("Couldnt convert value disclosure to str")
                            })
                            .unwrap()
                            .to_string()
                    })
                    .collect();
                let credential_id: String = value
                    .payload
                    .get("credential_id")
                    .ok_or_else(|| napi::Error::from_reason("'credential_id' must be in payload"))?
                    .as_str()
                    .ok_or_else(|| napi::Error::from_reason(""))?
                    .to_string();
                let credential_id = if credential_id.is_empty() {
                    None
                } else {
                    Some(credential_id)
                };
                CredentialDefinitionData::Ldp {
                    contexts,
                    vc_types,
                    credential_id,
                    lifetime,
                }
            }
        };
        Ok(result)
    }
}

/// An enum that defines the different formats of representations for credential status information.
///
/// # Variants:
///
/// * `TokenStatusList` - Indicates that the status is managed using a token-based status list.
/// * `BitstringStatusList` - Indicates that the status is managed using a bitstring representation
#[napi(js_name = "CredentialStatusInfoFormat")]
pub enum JsCredentialStatusInfoFormat {
    TokenStatusList,
    BitstringStatusList,
}

/// Credential Status
///
/// @property {CredentialStatusInfoFormat} format - format of `Credential Status Info`
/// @property {Record<string, any>} payload - payload of `Credential Status Info` depending on format
#[napi(js_name = "CredentialStatusInfo", object)]
pub struct JsCredentialStatusInfo {
    pub format: JsCredentialStatusInfoFormat,
    pub payload: JsonObject, // TODO: create an interface manually
}

impl TryFrom<CredentialStatusInfo> for JsCredentialStatusInfo {
    type Error = Error;

    fn try_from(value: CredentialStatusInfo) -> Result<Self, Error> {
        let result = match value {
            CredentialStatusInfo::TokenStatusList { idx, uri } => JsCredentialStatusInfo {
                format: JsCredentialStatusInfoFormat::TokenStatusList,
                payload: to_json_object(json!({ "idx": idx, "uri": uri }))?,
            },
            CredentialStatusInfo::BitstringStatusList => JsCredentialStatusInfo {
                format: JsCredentialStatusInfoFormat::BitstringStatusList,
                payload: JsonObject::new(),
            },
        };
        Ok(result)
    }
}

impl TryFrom<JsCredentialStatusInfo> for CredentialStatusInfo {
    type Error = Error;

    fn try_from(value: JsCredentialStatusInfo) -> Result<Self, Error> {
        let result = match value.format {
            JsCredentialStatusInfoFormat::TokenStatusList => {
                let idx: u32 = value
                    .payload
                    .get("idx")
                    .ok_or_else(|| napi::Error::from_reason("'idx' must be in payload"))?
                    .as_u64()
                    .ok_or_else(|| napi::Error::from_reason("'idx' must be an unsigned int"))?
                    .try_into()
                    .map_err(|_| napi::Error::from_reason("'idx' can not be converted to u32"))?;

                let uri: url::Url = value
                    .payload
                    .get("uri")
                    .ok_or_else(|| napi::Error::from_reason("'uri' must be in payload"))?
                    .as_str()
                    .ok_or_else(|| napi::Error::from_reason("'uri' must be a valid URL"))?
                    .try_into()
                    .map_err(|e: url::ParseError| Error::from_reason(e.to_string()))?;

                CredentialStatusInfo::TokenStatusList { idx, uri }
            }

            JsCredentialStatusInfoFormat::BitstringStatusList => {
                CredentialStatusInfo::BitstringStatusList
            }
        };
        Ok(result)
    }
}

#[napi(js_name = "VCStatusesDataFormat")]
pub enum JsVCStatusesDataFormat {
    StatusListToken,
    BitstringStatusList,
}

#[napi(js_name = "VCStatusesData", object)]
pub struct JsVCStatusesData {
    pub format: JsVCStatusesDataFormat,
    pub payload: JsonObject,
}

impl TryFrom<VCStatusesData> for JsVCStatusesData {
    type Error = Error;

    fn try_from(value: VCStatusesData) -> Result<Self, Error> {
        match value {
            VCStatusesData::StatusListToken(statuses) => Ok(JsVCStatusesData {
                format: JsVCStatusesDataFormat::StatusListToken,
                payload: to_json_object(statuses)?,
            }),

            VCStatusesData::BitstringStatusList => Ok(JsVCStatusesData {
                format: JsVCStatusesDataFormat::BitstringStatusList,
                payload: JsonObject::new(),
            }),

            _ => Err(napi::Error::from_reason("unsupported format")),
        }
    }
}

impl TryFrom<JsVCStatusesData> for VCStatusesData {
    type Error = Error;

    fn try_from(value: JsVCStatusesData) -> Result<Self, Error> {
        let result = match value.format {
            JsVCStatusesDataFormat::StatusListToken => {
                VCStatusesData::StatusListToken(from_json_object(value.payload)?)
            }

            JsVCStatusesDataFormat::BitstringStatusList => VCStatusesData::BitstringStatusList,
        };
        Ok(result)
    }
}

#[napi(js_name = "StatusListFmt")]
pub enum JsStatusListFmt {
    StatusListTokenJwt,
}

#[napi(js_name = "StatusList", object)]
pub struct JsStatusList {
    pub format: JsStatusListFmt,
    pub payload: JsonObject,
}

impl TryFrom<StatusList> for JsStatusList {
    type Error = Error;

    fn try_from(value: StatusList) -> Result<Self, Error> {
        match value {
            StatusList::StatusListTokenJwt(status_list) => Ok(JsStatusList {
                format: JsStatusListFmt::StatusListTokenJwt,
                payload: to_json_object(json!({"jwt": status_list}))?,
            }),
        }
    }
}

impl TryFrom<JsStatusList> for StatusList {
    type Error = Error;

    fn try_from(value: JsStatusList) -> Result<Self, Error> {
        let result = match value.format {
            JsStatusListFmt::StatusListTokenJwt => {
                let status_list_jwt = value
                    .payload
                    .get("jwt")
                    .ok_or_else(|| napi::Error::from_reason("'jwt' must be in payload"))?
                    .as_str()
                    .ok_or_else(|| napi::Error::from_reason("'jwt' must be a string"))?
                    .to_owned();

                StatusList::StatusListTokenJwt(status_list_jwt)
            }
        };

        Ok(result)
    }
}

#[napi(js_name = "VCStatusFormat")]
pub enum JsVCStatusFormat {
    StatusListToken,
}

#[napi(js_name = "VCStatus", object)]
pub struct JsVCStatus {
    pub format: JsVCStatusFormat,
    #[napi(ts_type = "VcTslStatusPayload | any")]
    pub payload: JsonObject,
}

#[napi(object, js_name = "VcTslStatusPayload")]
pub struct JsVcTslStatusPayload {
    pub status: TslVcStatusType,
    pub value: Option<u8>,
}

impl TryFrom<VCStatus> for JsVCStatus {
    type Error = Error;

    fn try_from(value: VCStatus) -> Result<Self, Error> {
        match value {
            VCStatus::StatusListToken(status) => {
                let payload_status = TslVcStatusType::from(status).to_string();
                let payload = match status {
                    status_list_token_jwt::VCStatus::Valid
                    | status_list_token_jwt::VCStatus::Invalid
                    | status_list_token_jwt::VCStatus::Suspended => {
                        json!({"status": payload_status})
                    }
                    status_list_token_jwt::VCStatus::AppSpecific(val) => {
                        json!({"status": payload_status, "value": val})
                    }
                };

                Ok(JsVCStatus {
                    format: JsVCStatusFormat::StatusListToken,
                    payload: to_json_object(payload)?,
                })
            }
        }
    }
}

impl TryFrom<JsVCStatus> for VCStatus {
    type Error = Error;

    fn try_from(value: JsVCStatus) -> Result<Self, Error> {
        let result = match value.format {
            JsVCStatusFormat::StatusListToken => {
                let status_str = value
                    .payload
                    .get("status")
                    .ok_or_else(|| napi::Error::from_reason("'status' must be in payload"))?
                    .as_str()
                    .ok_or_else(|| napi::Error::from_reason("'status' must be a string"))?;

                let status = match status_str {
                    "VALID" => Ok(status_list_token_jwt::VCStatus::Valid),
                    "INVALID" => Ok(status_list_token_jwt::VCStatus::Invalid),
                    "SUSPENDED" => Ok(status_list_token_jwt::VCStatus::Suspended),
                    "APPSPECIFIC" => {
                        let val: u8 = value
                            .payload
                            .get("value")
                            .ok_or_else(|| napi::Error::from_reason("'value' must be in payload"))?
                            .as_u64()
                            .ok_or_else(|| {
                                napi::Error::from_reason("'value' must be an unsigned int")
                            })?
                            .try_into()
                            .map_err(|_| {
                                napi::Error::from_reason("'value' can not be converted to u8")
                            })?;

                        Ok(status_list_token_jwt::VCStatus::AppSpecific(val))
                    }
                    _ => Err(napi::Error::from_reason(format!(
                        "Unsupported value of the 'status' field: {status_str}"
                    ))),
                }?;

                VCStatus::StatusListToken(status)
            }
        };

        Ok(result)
    }
}

/// Defines a token status list associated metadata for issuance.
///
/// @property {string} id: a unique identifier for the status list definition.
/// @property {StatusListFormat} format: the format of the {@link StatusList}
/// @property {KeyMetadata} keyMetadata: the metadata of the cryptographic key that is used to sign a status list.
#[napi(object, js_name = "StatusListDefinition")]
pub struct JsStatusListDefinition {
    pub id: String,
    pub format: JsStatusListFormat,
    pub key_metadata: JsKeyMetadata,
}

#[napi]
impl TryFrom<JsStatusListDefinition> for StatusListDefinition {
    type Error = Error;
    fn try_from(value: JsStatusListDefinition) -> Result<Self, Error> {
        Ok(Self {
            id: value.id,
            format: value.format.try_into()?,
            key_metadata: value.key_metadata.into(),
        })
    }
}

#[napi]
impl TryFrom<StatusListDefinition> for JsStatusListDefinition {
    type Error = Error;
    fn try_from(value: StatusListDefinition) -> Result<Self, Error> {
        Ok(Self {
            id: value.id,
            format: value.format.try_into()?,
            key_metadata: value.key_metadata.into(),
        })
    }
}

/// A metadata for the {@link VcCoreStatusIssuer}
///
/// This interface encapsulates all the necessary data required to handle the issuance of status lists.
///
/// @property {string} issuerId - ID of `Issuer`
/// @property {StatusListDefinition} supportedStatusLists - supported status lists
#[napi(object, js_name = "StatusIssuerMetadata")]
pub struct JsStatusIssuerMetadata {
    pub issuer_id: String,
    pub supported_status_lists: Vec<JsStatusListDefinition>,
}

#[napi]
impl TryFrom<JsStatusIssuerMetadata> for StatusIssuerMetadata {
    type Error = Error;
    fn try_from(value: JsStatusIssuerMetadata) -> Result<Self, Error> {
        Ok(Self {
            issuer_id: value.issuer_id,
            supported_status_lists: value
                .supported_status_lists
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<Vec<StatusListDefinition>, Error>>()?,
        })
    }
}

#[napi]
impl TryFrom<StatusIssuerMetadata> for JsStatusIssuerMetadata {
    type Error = Error;
    fn try_from(value: StatusIssuerMetadata) -> Result<Self, Error> {
        Ok(Self {
            issuer_id: value.issuer_id,
            supported_status_lists: value
                .supported_status_lists
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<Vec<JsStatusListDefinition>, Error>>()?,
        })
    }
}

#[napi(js_name = "CredentialOfferContentFormat")]
pub enum JsCredentialOfferContentFormat {
    CredDef,
    SupportedProofs,
}

/// An interface defining content for a {@link CredentialOffer}
///
/// @property {CredentialOfferContentFormat} format - format of `credential offer content`
/// @property {Record<string, any>} payload - value of `credential offer content`
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

/// A `CredentialOffer` entity.
///
/// Contains the data related to offered {@link Credential}.
///
/// Generated by `Issuer` to be used later by `Holder` to build a proper {@link CredentialRequest}.
///
/// @property {string} [credOfferId] - ID of `credential offer`
/// @property {string} issuerId - ID of `Issuer`
/// @property {string} credDefId - ID of {@link CredentialDefinition}
/// @property {CredentialOfferContent} credDefId - content of `credential offer`
/// @property {CredentialOfferData} protocolData - protocol data of `credential offer`
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

#[napi(js_name = "PresentationRestrictionValueType")]
pub enum JsPresentationRestrictionValueType {
    String,
    Pattern,
    Array,
}

#[napi(js_name = "InternalPresentationRestrictionValue", object)]
pub struct JsPresentationRestrictionValue {
    pub type_: JsPresentationRestrictionValueType,
    pub string: Option<String>,
    pub array: Option<Vec<Vec<String>>>,
}

impl TryFrom<JsPresentationRestrictionValue> for PresentationRestrictionValue {
    type Error = Error;
    fn try_from(value: JsPresentationRestrictionValue) -> Result<Self, Error> {
        match value.type_ {
            JsPresentationRestrictionValueType::String => {
                let string = value.string.ok_or(Error::from_reason(
                    "Could not parse PresentationRestrictionValue into string",
                ))?;
                Ok(PresentationRestrictionValue::Const(string))
            }
            JsPresentationRestrictionValueType::Pattern => {
                let string = value.string.ok_or(Error::from_reason(
                    "Could not parse PresentationRestrictionValue into string",
                ))?;
                Ok(PresentationRestrictionValue::Pattern(string))
            }
            JsPresentationRestrictionValueType::Array => {
                let array = value.array.ok_or(Error::from_reason(
                    "Could not parse PresentationRestrictionValue into Vec<Vec<String>> ",
                ))?;
                Ok(PresentationRestrictionValue::ArrayOfValues(array))
            }
        }
    }
}

impl TryFrom<PresentationRestrictionValue> for JsPresentationRestrictionValue {
    type Error = Error;
    fn try_from(value: PresentationRestrictionValue) -> Result<Self, Error> {
        match value {
            PresentationRestrictionValue::Const(s) => Ok(JsPresentationRestrictionValue {
                type_: JsPresentationRestrictionValueType::String,
                string: Some(s),
                array: None,
            }),
            PresentationRestrictionValue::Pattern(s) => Ok(JsPresentationRestrictionValue {
                type_: JsPresentationRestrictionValueType::Pattern,
                string: Some(s),
                array: None,
            }),
            PresentationRestrictionValue::ArrayOfValues(a) => Ok(JsPresentationRestrictionValue {
                type_: JsPresentationRestrictionValueType::Array,
                array: Some(a),
                string: None,
            }),
        }
    }
}

/// Represents a restrictions for presented credentials.
///
/// @property {Array<string>} fields - A list of field names that must be present in the credential.
/// @property {PresentationRestrictionValue} [value] - An optional value that the field(s) must match.
/// @property {boolean} optional - A flag indicates whether the specified field(s) is optional.
#[napi(js_name = "PresentationRestriction", object)]
pub struct JsPresentationRestriction {
    pub fields: Vec<String>,
    pub value: Option<JsPresentationRestrictionValue>,
    pub optional: bool,
}

impl TryFrom<JsPresentationRestriction> for PresentationRestriction {
    type Error = Error;
    fn try_from(value: JsPresentationRestriction) -> Result<Self, Error> {
        Ok(Self {
            fields: value.fields,
            value: value.value.map(|v| v.try_into()).transpose()?,
            optional: value.optional,
        })
    }
}

impl TryFrom<PresentationRestriction> for JsPresentationRestriction {
    type Error = Error;
    fn try_from(value: PresentationRestriction) -> Result<Self, Error> {
        Ok(Self {
            fields: value.fields,
            value: value.value.map(|v| v.try_into()).transpose()?,
            optional: value.optional,
        })
    }
}

/// An entity used to prepare a {@link Presentation} for the `Verifier`.
///
/// Contains the parameters used by `Holder` to find a suitable {@link Credential}s.
///
/// @property {string} id - ID of `presentation input`
/// @property {string} [format] - format of `presentation input`
/// @property {Array<PresentationRestriction>} [restrictions] - restrictions of `presentation input`
#[napi(js_name = "PresentationInput", object)]
pub struct JsPresentationInput {
    pub id: String,
    pub format: Option<String>,
    pub restrictions: Vec<JsPresentationRestriction>,
}

impl TryFrom<JsPresentationInput> for PresentationInput {
    type Error = Error;

    fn try_from(value: JsPresentationInput) -> Result<Self, Error> {
        let mut restrictions = vec![];
        for restriction in value.restrictions {
            restrictions.push(restriction.try_into()?);
        }
        Ok(Self {
            id: value.id,
            format: value.format,
            restrictions,
        })
    }
}

impl TryFrom<PresentationInput> for JsPresentationInput {
    type Error = Error;

    fn try_from(value: PresentationInput) -> Result<Self, Error> {
        let mut restrictions = vec![];
        for restriction in value.restrictions {
            restrictions.push(restriction.try_into()?);
        }
        Ok(Self {
            id: value.id,
            format: value.format,
            restrictions,
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

/// Verifiable Presentation (`VP`)
///
/// Each enum value represents different format of `VP` and contains an actual serializable `VP` body.
///
/// @property {PresentationFormat} format - format of `VP`
/// @property {string} payload - value of `VP` in a string representation
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

/// A protocol-specific data for the `Issuer`.
///
/// *NOTE*: will be extended in the next releases.
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

/// An interface that defines how to display the claim.
///
/// *NOTE*: will be extended in the next releases.
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

/// A `CredentialDefinition` for the `Issuer`.
///
/// Defines the Credential Schema and enlists the claims expected in the corresponding {@link Credential}.
/// Contains other various data necessary for creation of {@link Credential} as well.
///
/// @property {string} credDefId - ID of `credential definition`
/// @property {VCFormat} format - format of {@link Credential}
/// @property {Record<string, any>} claims - claims
/// @property {Record<string, any>} [supportedProofs] - supported proofs
/// @property {Array<Alg>} [supportedSigningAlgs] - supported signing `algorithms`
/// @property {Display} [display] - `display`
/// @property {Record<string, any>} [protocolData] - protocol data
/// @property {KeyMetadata} keyMetadata - key metadata
#[napi(js_name = "CredentialDefinition", object)]
pub struct JsCredentialDefinition {
    pub cred_def_id: String,
    pub format: JsVCFormat,
    pub claims: JsonObject,
    pub supported_proofs: Option<JsonObject>,
    pub supported_signing_algs: Option<Vec<JsAlg>>,
    pub display: Option<JsDisplay>,
    pub protocol_data: Option<JsCredentialDefinitionData>,
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
            protocol_data: Some(value.protocol_data.unwrap().try_into()?),
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
            protocol_data: Some(value.protocol_data.unwrap().try_into()?),
            key_metadata: value.key_metadata.into(),
        })
    }
}

/// A metadata for the `Issuer`.
///
/// Encapsulates all necessary data needed to handle issuance of the {@link Credential}s.
///
/// One `IssuerMetadata` supports multiple {@link CredentialDefinition}s.
///
/// @property {string} issuerId - ID of `Issuer`
/// @property {Array<CredentialDefinition>} credDefs - credential definitions
/// @property {IssuerMetadataData} [protocolData] - protocol metadata
#[napi(object, js_name = "IssuerMetadata")]
pub struct JsIssuerMetadata {
    pub issuer_id: String,
    pub cred_defs: Vec<JsCredentialDefinition>,
    pub protocol_data: Option<JsIssuerMetadataData>,
}

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

/// A metadata for the `Holder`.
///
/// Encapsulates all necessary data needed to request a {@link Credential}.
///
/// @property {string} clientId - ID of client
#[napi(js_name = "HolderMetadata", object)]
pub struct JsHolderMetadata {
    pub client_id: String,
    pub pop: JsProofOfPossessionMetadata,
}

impl TryFrom<JsHolderMetadata> for HolderMetadata {
    type Error = Error;

    fn try_from(value: JsHolderMetadata) -> Result<Self, Error> {
        Ok(Self {
            client_id: value.client_id,
            pop: value.pop.try_into()?,
        })
    }
}

impl TryFrom<HolderMetadata> for JsHolderMetadata {
    type Error = Error;

    fn try_from(value: HolderMetadata) -> Result<Self, Error> {
        Ok(Self {
            client_id: value.client_id,
            pop: value.pop.try_into()?,
        })
    }
}

/// A metadata for the `ProofOfPossessionMetadata`.
///
/// Encapsulates all necessary data needed to generate a proof of possession.
#[napi(js_name = "ProofOfPossessionMetadata", object)]
pub struct JsProofOfPossessionMetadata {
    pub lifetime: Option<i64>,
    pub not_before: Option<JsProofOfPossessionNotBefore>,
}

impl TryFrom<JsProofOfPossessionMetadata> for ProofOfPossessionMetadata {
    type Error = Error;

    fn try_from(value: JsProofOfPossessionMetadata) -> Result<Self, Error> {
        let lifetime = if let Some(time) = value.lifetime {
            Duration::seconds(time)
        } else {
            Duration::minutes(DEFAULT_POP_LIFETIME_MINUTES)
        };
        let nbf = if let Some(val) = value.not_before {
            Some(val.try_into()?)
        } else {
            None
        };
        Ok(Self {
            lifetime,
            not_before: nbf,
        })
    }
}

impl TryFrom<ProofOfPossessionMetadata> for JsProofOfPossessionMetadata {
    type Error = Error;

    fn try_from(value: ProofOfPossessionMetadata) -> Result<Self, Error> {
        let js_not_before = if let Some(not_before) = value.not_before {
            Some(not_before.try_into()?)
        } else {
            None
        };
        Ok(Self {
            lifetime: Some(value.lifetime.whole_seconds()),
            not_before: js_not_before,
        })
    }
}

#[napi(js_name = "InnerProofOfPossessionNotBefore", object)]
pub struct JsProofOfPossessionNotBefore {
    pub strategy: JsProofOfPossessionNotBeforeStrategy,
    pub fixed: Option<DateTime<Utc>>,
    pub delay: Option<i64>,
    pub leeway: Option<i64>,
}

/// Configures how Not Before claim (see [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)) must be specified.
#[napi(js_name = "InnerProofOfPossessionNotBeforeStrategy")]
pub enum JsProofOfPossessionNotBeforeStrategy {
    /// Sets nbf the same as iat.
    AsIssuedAt,
    /// Sets nbf to provided timestamp.
    Fixed,
    /// Sets nbf with a given delay from iat.
    ///
    /// Example:
    ///     `iat` is 10:00:00;
    ///     `delay` is 5 min;
    ///     then `nbf` will be 10:05:00.
    Delay,
    /// Sets nbf with a given leeway from iat.
    ///
    /// Example:
    ///     `iat` is 10:00:00;
    ///     `leeway` is 5 min;
    ///     then `nbf` will be 9:55:00.
    Leeway,
}

impl TryFrom<JsProofOfPossessionNotBefore> for ProofOfPossessionNotBefore {
    type Error = Error;

    fn try_from(js_not_before: JsProofOfPossessionNotBefore) -> Result<Self, Error> {
        Ok(match js_not_before.strategy {
            JsProofOfPossessionNotBeforeStrategy::AsIssuedAt => {
                ProofOfPossessionNotBefore::AsIssuedAt
            }
            JsProofOfPossessionNotBeforeStrategy::Fixed => {
                let fixed = js_not_before
                    .fixed
                    .ok_or(Error::from_reason(
                        "Fixed PoP generation strategy requires fixed time to be specified",
                    ))?
                    .try_into_time()
                    .map_err(map_component_range_err)?;
                ProofOfPossessionNotBefore::Fixed(fixed)
            }
            JsProofOfPossessionNotBeforeStrategy::Delay => {
                let delay = js_not_before.delay.ok_or(Error::from_reason(
                    "Delay PoP generation strategy requires delay time to be specified",
                ))?;
                ProofOfPossessionNotBefore::Delay(Duration::seconds(delay))
            }
            JsProofOfPossessionNotBeforeStrategy::Leeway => {
                let leeway = js_not_before.leeway.ok_or(Error::from_reason(
                    "Leeway PoP generation strategy requires leeway time to be specified",
                ))?;
                ProofOfPossessionNotBefore::Leeway(Duration::seconds(leeway))
            }
        })
    }
}

impl TryFrom<ProofOfPossessionNotBefore> for JsProofOfPossessionNotBefore {
    type Error = Error;

    fn try_from(value: ProofOfPossessionNotBefore) -> Result<Self, Error> {
        Ok(match value {
            ProofOfPossessionNotBefore::AsIssuedAt => JsProofOfPossessionNotBefore {
                strategy: JsProofOfPossessionNotBeforeStrategy::AsIssuedAt,
                fixed: None,
                delay: None,
                leeway: None,
            },
            ProofOfPossessionNotBefore::Fixed(time) => JsProofOfPossessionNotBefore {
                strategy: JsProofOfPossessionNotBeforeStrategy::Fixed,
                fixed: Some(time.try_into_chrono().map_err(|_| {
                    Error::from_reason(
                        "Failed to convertd time::OffsetDateTime to chrono::DateTime",
                    )
                })?),
                delay: None,
                leeway: None,
            },
            ProofOfPossessionNotBefore::Delay(delay) => JsProofOfPossessionNotBefore {
                strategy: JsProofOfPossessionNotBeforeStrategy::Delay,
                fixed: None,
                delay: Some(delay.whole_seconds()),
                leeway: None,
            },
            ProofOfPossessionNotBefore::Leeway(leeway) => JsProofOfPossessionNotBefore {
                strategy: JsProofOfPossessionNotBeforeStrategy::Leeway,
                fixed: None,
                delay: None,
                leeway: Some(leeway.whole_seconds()),
            },
        })
    }
}
#[napi(js_name = "HolderBinder", object)]
pub struct JsHolderBinder {
    pub nonce: String,
    pub verifier_id: String,
}
impl From<JsHolderBinder> for HolderBinder {
    fn from(value: JsHolderBinder) -> Self {
        HolderBinder {
            nonce: Nonce::from_secret(value.nonce),
            verifier_id: value.verifier_id,
        }
    }
}

impl From<HolderBinder> for JsHolderBinder {
    fn from(value: HolderBinder) -> Self {
        JsHolderBinder {
            nonce: value.nonce.secret().to_string(),
            verifier_id: value.verifier_id,
        }
    }
}

fn map_component_range_err(err: ComponentRange) -> Error {
    Error::from_reason(format!("{}", err))
}
