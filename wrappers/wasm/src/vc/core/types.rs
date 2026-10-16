use crate::utils::js_err;
use equs_sdk::crypto::Alg;
use equs_sdk::nonce::Nonce;
use equs_sdk::vc::core::PopFormat;
use equs_sdk::vc::core::{
    CredentialDefinition, CredentialDefinitionData, CredentialOffer, CredentialOfferContent,
    CredentialOfferData, CredentialRequest, CredentialRequestData, CredentialStatusInfo,
    DEFAULT_POP_LIFETIME_MINUTES, Display, HolderBinder, HolderMetadata, IssuerMetadata,
    IssuerMetadataData, KeyMetadata, PresentationInput, PresentationRestriction,
    PresentationRestrictionValue, Proof, ProofOfPossessionMetadata,
    ProofOfPossessionNotBefore as SDKProofOfPossessionNotBefore, StatusIssuerMetadata,
    StatusListDefinition,
};
use equs_sdk::vc::status_formats::StatusListFormat;
use equs_sdk::vc::status_formats::status_list_token_jwt::{
    SLMetadata, VCStatus as SdkTslVCStatus, VCStatuses as SdkVCStatuses,
};
use equs_sdk::vc::{Presentation, StatusList, VCFormat, VCStatus, VCStatusesData};
use equs_sdk::{Duration, OffsetDateTime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use wasm_bindgen::JsError;

// ===== Proof =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmProof {
    pub format: String,
    pub proof: String,
}

impl From<WasmProof> for Proof {
    fn from(v: WasmProof) -> Self {
        Proof {
            format: v.format,
            proof: v.proof,
        }
    }
}

impl From<Proof> for WasmProof {
    fn from(v: Proof) -> Self {
        WasmProof {
            format: v.format,
            proof: v.proof,
        }
    }
}

// ===== CredentialRequestData =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCredentialRequestData {
    pub proof_tolerance: Option<i64>, // seconds
}

impl From<WasmCredentialRequestData> for CredentialRequestData {
    fn from(v: WasmCredentialRequestData) -> Self {
        CredentialRequestData {
            proof_tolerance: v.proof_tolerance.map(Duration::seconds),
        }
    }
}

impl From<CredentialRequestData> for WasmCredentialRequestData {
    fn from(v: CredentialRequestData) -> Self {
        WasmCredentialRequestData {
            proof_tolerance: v.proof_tolerance.map(|d| d.whole_seconds()),
        }
    }
}

// ===== CredentialRequest =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCredentialRequest {
    pub cred_def_id: String,
    pub cred_offer_id: Option<String>,
    pub proof: WasmProof,
    pub protocol_data: Option<WasmCredentialRequestData>,
}

impl From<WasmCredentialRequest> for CredentialRequest {
    fn from(v: WasmCredentialRequest) -> Self {
        CredentialRequest {
            cred_def_id: v.cred_def_id,
            cred_offer_id: v.cred_offer_id,
            proof: v.proof.into(),
            protocol_data: v.protocol_data.map(Into::into),
        }
    }
}

impl From<CredentialRequest> for WasmCredentialRequest {
    fn from(v: CredentialRequest) -> Self {
        WasmCredentialRequest {
            cred_def_id: v.cred_def_id,
            cred_offer_id: v.cred_offer_id,
            proof: v.proof.into(),
            protocol_data: v.protocol_data.map(Into::into),
        }
    }
}

// Shared empty payload for unit-like variants that must serialize as `{ "payload": {} }`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EmptyPayload {}

// ===== CredentialDefinitionData (format + payload) =====
// Adjacently-tagged: `{ "format": "sdJwt", "payload": { ... } }`.
// Field names inside the Ldp variant intentionally use snake_case (`vc_types`,
// `credential_id`) because the existing wire format predates the camelCase convention.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmCredentialDefinitionData {
    SdJwt {
        vct: String,
        disclosures: Vec<String>,
        lifetime: Option<i64>, // milliseconds
    },
    Ldp {
        contexts: Vec<String>,
        #[serde(rename = "vc_types")]
        vc_types: Vec<String>,
        #[serde(rename = "credential_id")]
        credential_id: Option<String>,
        lifetime: Option<i64>, // milliseconds
    },
}

impl TryFrom<WasmCredentialDefinitionData> for CredentialDefinitionData {
    type Error = JsError;

    fn try_from(v: WasmCredentialDefinitionData) -> Result<Self, JsError> {
        match v {
            WasmCredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime,
            } => Ok(CredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime: lifetime.map(Duration::milliseconds),
            }),
            WasmCredentialDefinitionData::Ldp {
                contexts,
                vc_types,
                credential_id,
                lifetime,
            } => Ok(CredentialDefinitionData::Ldp {
                contexts,
                vc_types,
                credential_id,
                lifetime: lifetime.map(Duration::milliseconds),
            }),
        }
    }
}

impl TryFrom<CredentialDefinitionData> for WasmCredentialDefinitionData {
    type Error = JsError;

    fn try_from(v: CredentialDefinitionData) -> Result<Self, JsError> {
        match v {
            CredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime,
            } => Ok(WasmCredentialDefinitionData::SdJwt {
                vct,
                disclosures,
                lifetime: lifetime.map(|d| d.whole_milliseconds() as i64),
            }),
            CredentialDefinitionData::Ldp {
                contexts,
                vc_types,
                credential_id,
                lifetime,
            } => Ok(WasmCredentialDefinitionData::Ldp {
                contexts,
                vc_types,
                credential_id,
                lifetime: lifetime.map(|d| d.whole_milliseconds() as i64),
            }),
            _ => Err(JsError::new("Unsupported CredentialDefinitionData variant")),
        }
    }
}

// ===== CredentialStatusInfo (format + payload) =====
// Adjacently-tagged: `{ "format": "tokenStatusList", "payload": { "idx": 0, "uri": "..." } }`.
// BitstringStatusList uses EmptyPayload to preserve `payload: {}` in the wire format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmCredentialStatusInfo {
    TokenStatusList { idx: u32, uri: String },
    BitstringStatusList(EmptyPayload),
}

impl TryFrom<WasmCredentialStatusInfo> for CredentialStatusInfo {
    type Error = JsError;

    fn try_from(v: WasmCredentialStatusInfo) -> Result<Self, JsError> {
        match v {
            WasmCredentialStatusInfo::TokenStatusList { idx, uri } => {
                let uri = uri.as_str().try_into().map_err(js_err)?;
                Ok(CredentialStatusInfo::TokenStatusList { idx, uri })
            }
            WasmCredentialStatusInfo::BitstringStatusList(_) => {
                Ok(CredentialStatusInfo::BitstringStatusList)
            }
        }
    }
}

impl TryFrom<CredentialStatusInfo> for WasmCredentialStatusInfo {
    type Error = JsError;

    fn try_from(v: CredentialStatusInfo) -> Result<Self, JsError> {
        match v {
            CredentialStatusInfo::TokenStatusList { idx, uri } => {
                Ok(WasmCredentialStatusInfo::TokenStatusList {
                    idx,
                    uri: uri.to_string(),
                })
            }
            CredentialStatusInfo::BitstringStatusList => Ok(
                WasmCredentialStatusInfo::BitstringStatusList(EmptyPayload {}),
            ),
        }
    }
}

// ===== VCStatusesData =====
// Adjacently-tagged: `{ "format": "statusListToken", "payload": { ... } }`.
// BitstringStatusList uses EmptyPayload to preserve `payload: {}` in the wire format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmVCStatusesData {
    StatusListToken { statuses: HashMap<String, u8> },
    BitstringStatusList(EmptyPayload),
}

impl TryFrom<WasmVCStatusesData> for VCStatusesData {
    type Error = JsError;

    fn try_from(v: WasmVCStatusesData) -> Result<Self, JsError> {
        match v {
            WasmVCStatusesData::StatusListToken { statuses } => {
                let mut sdk_statuses = SdkVCStatuses::new();
                for (k, v) in statuses {
                    let idx = k
                        .parse::<usize>()
                        .map_err(|_| JsError::new(&format!("Invalid status index: {k}")))?;
                    sdk_statuses.set(idx, SdkTslVCStatus::from(v));
                }
                Ok(VCStatusesData::StatusListToken(sdk_statuses))
            }
            WasmVCStatusesData::BitstringStatusList(_) => Ok(VCStatusesData::BitstringStatusList),
        }
    }
}

impl TryFrom<VCStatusesData> for WasmVCStatusesData {
    type Error = JsError;

    fn try_from(v: VCStatusesData) -> Result<Self, JsError> {
        match v {
            VCStatusesData::StatusListToken(statuses) => Ok(WasmVCStatusesData::StatusListToken {
                statuses: statuses
                    .statuses()
                    .iter()
                    .map(|(&k, &v)| (k.to_string(), v))
                    .collect(),
            }),
            VCStatusesData::BitstringStatusList => {
                Ok(WasmVCStatusesData::BitstringStatusList(EmptyPayload {}))
            }
            _ => Err(JsError::new("Unsupported VCStatusesData format")),
        }
    }
}

// ===== StatusList (format + payload) =====
// Adjacently-tagged: `{ "format": "statusListTokenJwt", "payload": { "jwt": "..." } }`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmStatusList {
    StatusListTokenJwt { jwt: String },
}

impl TryFrom<StatusList> for WasmStatusList {
    type Error = JsError;

    fn try_from(v: StatusList) -> Result<Self, JsError> {
        match v {
            StatusList::StatusListTokenJwt(jwt) => Ok(WasmStatusList::StatusListTokenJwt { jwt }),
        }
    }
}

impl TryFrom<WasmStatusList> for StatusList {
    type Error = JsError;

    fn try_from(v: WasmStatusList) -> Result<Self, JsError> {
        match v {
            WasmStatusList::StatusListTokenJwt { jwt } => Ok(StatusList::StatusListTokenJwt(jwt)),
        }
    }
}

// ===== VCStatus =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WasmVCStatusFormat {
    StatusListToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WasmTslVcStatusKind {
    #[serde(rename = "VALID")]
    Valid,
    #[serde(rename = "INVALID")]
    Invalid,
    #[serde(rename = "SUSPENDED")]
    Suspended,
    #[serde(rename = "APPSPECIFIC")]
    AppSpecific,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmVCStatusPayload {
    pub status: WasmTslVcStatusKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmVCStatus {
    pub format: WasmVCStatusFormat,
    pub payload: WasmVCStatusPayload,
}

impl TryFrom<VCStatus> for WasmVCStatus {
    type Error = JsError;

    fn try_from(v: VCStatus) -> Result<Self, JsError> {
        match v {
            VCStatus::StatusListToken(status) => {
                let (kind, value) = match status {
                    SdkTslVCStatus::Valid => (WasmTslVcStatusKind::Valid, None),
                    SdkTslVCStatus::Invalid => (WasmTslVcStatusKind::Invalid, None),
                    SdkTslVCStatus::Suspended => (WasmTslVcStatusKind::Suspended, None),
                    SdkTslVCStatus::AppSpecific(val) => {
                        (WasmTslVcStatusKind::AppSpecific, Some(val))
                    }
                };
                Ok(WasmVCStatus {
                    format: WasmVCStatusFormat::StatusListToken,
                    payload: WasmVCStatusPayload {
                        status: kind,
                        value,
                    },
                })
            }
        }
    }
}

impl TryFrom<WasmVCStatus> for VCStatus {
    type Error = JsError;

    fn try_from(v: WasmVCStatus) -> Result<Self, JsError> {
        match v.format {
            WasmVCStatusFormat::StatusListToken => {
                let tsl = match v.payload.status {
                    WasmTslVcStatusKind::Valid => SdkTslVCStatus::Valid,
                    WasmTslVcStatusKind::Invalid => SdkTslVCStatus::Invalid,
                    WasmTslVcStatusKind::Suspended => SdkTslVCStatus::Suspended,
                    WasmTslVcStatusKind::AppSpecific => SdkTslVCStatus::AppSpecific(
                        v.payload
                            .value
                            .ok_or_else(|| JsError::new("'value' required for APPSPECIFIC"))?,
                    ),
                };
                Ok(VCStatus::StatusListToken(tsl))
            }
        }
    }
}

// ===== StatusListFormat (format + payload) =====
// Adjacently-tagged: `{ "format": "statusListTokenJwt", "payload": { ... } }`.
// StatusListTokenCwt uses EmptyPayload to preserve `payload: {}` in the wire format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmStatusListFormat {
    StatusListTokenJwt(SLMetadata),
    StatusListTokenCwt(EmptyPayload),
}

impl TryFrom<WasmStatusListFormat> for StatusListFormat {
    type Error = JsError;

    fn try_from(v: WasmStatusListFormat) -> Result<Self, JsError> {
        match v {
            WasmStatusListFormat::StatusListTokenJwt(metadata) => {
                Ok(StatusListFormat::StatusListTokenJwt(metadata))
            }
            WasmStatusListFormat::StatusListTokenCwt(_) => Ok(StatusListFormat::StatusListTokenCwt),
        }
    }
}

impl TryFrom<StatusListFormat> for WasmStatusListFormat {
    type Error = JsError;

    fn try_from(v: StatusListFormat) -> Result<Self, JsError> {
        match v {
            StatusListFormat::StatusListTokenJwt(meta) => {
                Ok(WasmStatusListFormat::StatusListTokenJwt(meta))
            }
            StatusListFormat::StatusListTokenCwt => {
                Ok(WasmStatusListFormat::StatusListTokenCwt(EmptyPayload {}))
            }
        }
    }
}

// ===== StatusListDefinition =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmStatusListDefinition {
    pub id: String,
    pub format: WasmStatusListFormat,
    pub key_metadata: KeyMetadata,
}

impl TryFrom<WasmStatusListDefinition> for StatusListDefinition {
    type Error = JsError;

    fn try_from(v: WasmStatusListDefinition) -> Result<Self, JsError> {
        Ok(StatusListDefinition {
            id: v.id,
            format: v.format.try_into()?,
            key_metadata: v.key_metadata,
        })
    }
}

impl TryFrom<StatusListDefinition> for WasmStatusListDefinition {
    type Error = JsError;

    fn try_from(v: StatusListDefinition) -> Result<Self, JsError> {
        Ok(WasmStatusListDefinition {
            id: v.id,
            format: v.format.try_into()?,
            key_metadata: v.key_metadata,
        })
    }
}

// ===== StatusIssuerMetadata =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmStatusIssuerMetadata {
    pub issuer_id: String,
    pub supported_status_lists: Vec<WasmStatusListDefinition>,
}

impl TryFrom<WasmStatusIssuerMetadata> for StatusIssuerMetadata {
    type Error = JsError;

    fn try_from(v: WasmStatusIssuerMetadata) -> Result<Self, JsError> {
        Ok(StatusIssuerMetadata {
            issuer_id: v.issuer_id,
            supported_status_lists: v
                .supported_status_lists
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

// ===== CredentialOfferContent (format + payload) =====
// Adjacently-tagged: `{ "format": "credDef", "payload": { ... } }`.
// The payload is a `serde_json::Value` so the inner shape comes straight from
// the SDK's `CredentialDefinition` serde (default snake_case). Mirrors Node.js's
// untyped `to_json_object(SDK CredentialDefinition)` pass-through.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmCredentialOfferContent {
    CredDef(Value),
    SupportedProofs(Option<HashMap<PopFormat, Vec<Alg>>>),
}

impl TryFrom<WasmCredentialOfferContent> for CredentialOfferContent {
    type Error = JsError;

    fn try_from(v: WasmCredentialOfferContent) -> Result<Self, JsError> {
        match v {
            WasmCredentialOfferContent::CredDef(payload) => Ok(CredentialOfferContent::CredDef(
                serde_json::from_value(payload).map_err(js_err)?,
            )),
            WasmCredentialOfferContent::SupportedProofs(supported) => {
                Ok(CredentialOfferContent::SupportedProofs(supported))
            }
        }
    }
}

impl TryFrom<CredentialOfferContent> for WasmCredentialOfferContent {
    type Error = JsError;

    fn try_from(v: CredentialOfferContent) -> Result<Self, JsError> {
        match v {
            CredentialOfferContent::CredDef(cred_def) => Ok(WasmCredentialOfferContent::CredDef(
                serde_json::to_value(cred_def).map_err(js_err)?,
            )),
            CredentialOfferContent::SupportedProofs(supported) => {
                Ok(WasmCredentialOfferContent::SupportedProofs(supported))
            }
        }
    }
}

// ===== CredentialOffer =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCredentialOffer {
    pub cred_offer_id: Option<String>,
    pub issuer_id: String,
    pub cred_def_id: String,
    pub content: WasmCredentialOfferContent,
    pub protocol_data: Option<Value>,
}

impl TryFrom<WasmCredentialOffer> for CredentialOffer {
    type Error = JsError;

    fn try_from(v: WasmCredentialOffer) -> Result<Self, JsError> {
        Ok(CredentialOffer {
            cred_offer_id: v.cred_offer_id,
            issuer_id: v.issuer_id,
            cred_def_id: v.cred_def_id,
            content: v.content.try_into()?,
            protocol_data: v.protocol_data.map(|_| CredentialOfferData {}),
        })
    }
}

impl TryFrom<CredentialOffer> for WasmCredentialOffer {
    type Error = JsError;

    fn try_from(v: CredentialOffer) -> Result<Self, JsError> {
        Ok(WasmCredentialOffer {
            cred_offer_id: v.cred_offer_id,
            issuer_id: v.issuer_id,
            cred_def_id: v.cred_def_id,
            content: v.content.try_into()?,
            protocol_data: v.protocol_data.map(|_| Value::Object(Default::default())),
        })
    }
}

// ===== PresentationRestrictionValue =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WasmPresentationRestrictionValueType {
    String,
    Pattern,
    Array,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmPresentationRestrictionValue {
    #[serde(rename = "type")]
    pub type_: WasmPresentationRestrictionValueType,
    pub string: Option<String>,
    pub array: Option<Vec<Vec<String>>>,
}

impl TryFrom<WasmPresentationRestrictionValue> for PresentationRestrictionValue {
    type Error = JsError;

    fn try_from(v: WasmPresentationRestrictionValue) -> Result<Self, JsError> {
        match v.type_ {
            WasmPresentationRestrictionValueType::String => {
                Ok(PresentationRestrictionValue::Const(v.string.ok_or_else(
                    || JsError::new("'string' required for String type"),
                )?))
            }
            WasmPresentationRestrictionValueType::Pattern => {
                Ok(PresentationRestrictionValue::Pattern(v.string.ok_or_else(
                    || JsError::new("'string' required for Pattern type"),
                )?))
            }
            WasmPresentationRestrictionValueType::Array => {
                Ok(PresentationRestrictionValue::ArrayOfValues(
                    v.array
                        .ok_or_else(|| JsError::new("'array' required for Array type"))?,
                ))
            }
        }
    }
}

impl TryFrom<PresentationRestrictionValue> for WasmPresentationRestrictionValue {
    type Error = JsError;

    fn try_from(v: PresentationRestrictionValue) -> Result<Self, JsError> {
        match v {
            PresentationRestrictionValue::Const(s) => Ok(WasmPresentationRestrictionValue {
                type_: WasmPresentationRestrictionValueType::String,
                string: Some(s),
                array: None,
            }),
            PresentationRestrictionValue::Pattern(s) => Ok(WasmPresentationRestrictionValue {
                type_: WasmPresentationRestrictionValueType::Pattern,
                string: Some(s),
                array: None,
            }),
            PresentationRestrictionValue::ArrayOfValues(a) => {
                Ok(WasmPresentationRestrictionValue {
                    type_: WasmPresentationRestrictionValueType::Array,
                    string: None,
                    array: Some(a),
                })
            }
        }
    }
}

// ===== PresentationRestriction =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmPresentationRestriction {
    pub fields: Vec<String>,
    pub value: Option<WasmPresentationRestrictionValue>,
    pub optional: bool,
}

impl TryFrom<WasmPresentationRestriction> for PresentationRestriction {
    type Error = JsError;

    fn try_from(v: WasmPresentationRestriction) -> Result<Self, JsError> {
        Ok(PresentationRestriction {
            fields: v.fields,
            value: v.value.map(TryInto::try_into).transpose()?,
            optional: v.optional,
        })
    }
}

impl TryFrom<PresentationRestriction> for WasmPresentationRestriction {
    type Error = JsError;

    fn try_from(v: PresentationRestriction) -> Result<Self, JsError> {
        Ok(WasmPresentationRestriction {
            fields: v.fields,
            value: v.value.map(TryInto::try_into).transpose()?,
            optional: v.optional,
        })
    }
}

// ===== PresentationInput =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmPresentationInput {
    pub id: String,
    pub format: Option<String>,
    pub restrictions: Vec<WasmPresentationRestriction>,
}

impl TryFrom<WasmPresentationInput> for PresentationInput {
    type Error = JsError;

    fn try_from(v: WasmPresentationInput) -> Result<Self, JsError> {
        Ok(PresentationInput {
            id: v.id,
            format: v.format,
            restrictions: v
                .restrictions
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<PresentationInput> for WasmPresentationInput {
    type Error = JsError;

    fn try_from(v: PresentationInput) -> Result<Self, JsError> {
        Ok(WasmPresentationInput {
            id: v.id,
            format: v.format,
            restrictions: v
                .restrictions
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

// ===== Presentation (format + payload) =====
// Adjacently-tagged: `{ "format": "jwtVp", "payload": "..." }`.
// JwtVp and LdpVp carry a JSON-stringified value; SdJwtVp carries the raw token string.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "format", content = "payload", rename_all = "camelCase")]
pub enum WasmPresentation {
    JwtVp(String),
    LdpVp(String),
    SdJwtVp(String),
}

impl TryFrom<WasmPresentation> for Presentation {
    type Error = JsError;

    fn try_from(v: WasmPresentation) -> Result<Self, JsError> {
        match v {
            WasmPresentation::JwtVp(s) => Ok(Presentation::JwtVp(
                serde_json::from_str(&s).map_err(js_err)?,
            )),
            WasmPresentation::LdpVp(s) => Ok(Presentation::LdpVp(
                serde_json::from_str(&s).map_err(js_err)?,
            )),
            WasmPresentation::SdJwtVp(s) => Ok(Presentation::SdJwtVp(s)),
        }
    }
}

impl TryFrom<Presentation> for WasmPresentation {
    type Error = JsError;

    fn try_from(v: Presentation) -> Result<Self, JsError> {
        match v {
            Presentation::JwtVp(inner) => Ok(WasmPresentation::JwtVp(
                serde_json::to_string(&inner).map_err(js_err)?,
            )),
            Presentation::LdpVp(inner) => Ok(WasmPresentation::LdpVp(
                serde_json::to_string(&inner).map_err(js_err)?,
            )),
            Presentation::SdJwtVp(inner) => Ok(WasmPresentation::SdJwtVp(inner)),
            _ => Err(JsError::new("Unsupported presentation format")),
        }
    }
}

// ===== CredentialDefinition =====
//
// `WasmCredentialDefinition` (camelCase) is used at typed top-level slots
// (e.g. `IssuerMetadata.credDefs[]`) to mirror Node.js's NAPI auto-camelCased
// `JsCredentialDefinition`. For the `CredentialOfferContent::CredDef` inner
// payload — which Node.js exposes via untyped `to_json_object(SDK CredentialDefinition)`
// pass-through (snake_case) — see the `serde_json::Value` payload on
// `WasmCredentialOfferContent::CredDef`.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCredentialDefinition {
    pub cred_def_id: String,
    pub format: VCFormat,
    pub claims: Value,
    pub supported_proofs: Option<Value>,
    pub supported_signing_algs: Option<Vec<Alg>>,
    pub display: Option<Value>,
    pub protocol_data: Option<WasmCredentialDefinitionData>,
    pub key_metadata: KeyMetadata,
}

impl TryFrom<WasmCredentialDefinition> for CredentialDefinition {
    type Error = JsError;

    fn try_from(v: WasmCredentialDefinition) -> Result<Self, JsError> {
        let claims: HashMap<String, Display> = v
            .claims
            .as_object()
            .map(|obj| obj.keys().map(|k| (k.clone(), Display)).collect())
            .unwrap_or_default();

        let supported_proofs = v
            .supported_proofs
            .map(|val| serde_json::from_value(val).map_err(js_err))
            .transpose()?;

        Ok(CredentialDefinition {
            cred_def_id: v.cred_def_id,
            format: v.format,
            claims,
            supported_proofs,
            supported_signing_algs: v.supported_signing_algs,
            display: None, // display field is not currently bridged across the WASM boundary
            protocol_data: v.protocol_data.map(TryInto::try_into).transpose()?,
            key_metadata: v.key_metadata,
        })
    }
}

impl TryFrom<CredentialDefinition> for WasmCredentialDefinition {
    type Error = JsError;

    fn try_from(v: CredentialDefinition) -> Result<Self, JsError> {
        let claims_keys: serde_json::Map<String, Value> =
            v.claims.keys().map(|k| (k.clone(), Value::Null)).collect();

        let supported_proofs = v
            .supported_proofs
            .map(|val| serde_json::to_value(val).map_err(js_err))
            .transpose()?;

        Ok(WasmCredentialDefinition {
            cred_def_id: v.cred_def_id,
            format: v.format,
            claims: Value::Object(claims_keys),
            supported_proofs,
            supported_signing_algs: v.supported_signing_algs,
            display: None, // display field is not currently bridged across the WASM boundary
            protocol_data: v.protocol_data.map(TryInto::try_into).transpose()?,
            key_metadata: v.key_metadata,
        })
    }
}

// ===== IssuerMetadata =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmIssuerMetadata {
    pub issuer_id: String,
    pub cred_defs: Vec<WasmCredentialDefinition>,
    pub protocol_data: Option<bool>,
}

impl TryFrom<WasmIssuerMetadata> for IssuerMetadata {
    type Error = JsError;

    fn try_from(v: WasmIssuerMetadata) -> Result<Self, JsError> {
        Ok(IssuerMetadata {
            issuer_id: v.issuer_id,
            cred_defs: v
                .cred_defs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            protocol_data: if v.protocol_data.unwrap_or(false) {
                Some(IssuerMetadataData {})
            } else {
                None
            },
        })
    }
}

impl TryFrom<IssuerMetadata> for WasmIssuerMetadata {
    type Error = JsError;

    fn try_from(v: IssuerMetadata) -> Result<Self, JsError> {
        Ok(WasmIssuerMetadata {
            issuer_id: v.issuer_id,
            cred_defs: v
                .cred_defs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            protocol_data: Some(v.protocol_data.is_some()),
        })
    }
}

// ===== ProofOfPossessionNotBefore =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WasmProofOfPossessionNotBeforeStrategy {
    AsIssuedAt,
    Fixed,
    Delay,
    Leeway,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmProofOfPossessionNotBefore {
    pub strategy: WasmProofOfPossessionNotBeforeStrategy,
    pub fixed: Option<i64>,  // Unix timestamp in seconds
    pub delay: Option<i64>,  // seconds
    pub leeway: Option<i64>, // seconds
}

impl TryFrom<WasmProofOfPossessionNotBefore> for SDKProofOfPossessionNotBefore {
    type Error = JsError;

    fn try_from(v: WasmProofOfPossessionNotBefore) -> Result<Self, JsError> {
        match v.strategy {
            WasmProofOfPossessionNotBeforeStrategy::AsIssuedAt => {
                Ok(SDKProofOfPossessionNotBefore::AsIssuedAt)
            }
            WasmProofOfPossessionNotBeforeStrategy::Fixed => {
                let secs = v
                    .fixed
                    .ok_or_else(|| JsError::new("Fixed strategy requires 'fixed' (seconds)"))?;
                let time = OffsetDateTime::from_unix_timestamp(secs).map_err(js_err)?;
                Ok(SDKProofOfPossessionNotBefore::Fixed(time))
            }
            WasmProofOfPossessionNotBeforeStrategy::Delay => {
                let delay = v
                    .delay
                    .ok_or_else(|| JsError::new("Delay strategy requires 'delay' (seconds)"))?;
                Ok(SDKProofOfPossessionNotBefore::Delay(Duration::seconds(
                    delay,
                )))
            }
            WasmProofOfPossessionNotBeforeStrategy::Leeway => {
                let leeway = v
                    .leeway
                    .ok_or_else(|| JsError::new("Leeway strategy requires 'leeway' (seconds)"))?;
                Ok(SDKProofOfPossessionNotBefore::Leeway(Duration::seconds(
                    leeway,
                )))
            }
        }
    }
}

impl TryFrom<SDKProofOfPossessionNotBefore> for WasmProofOfPossessionNotBefore {
    type Error = JsError;

    fn try_from(v: SDKProofOfPossessionNotBefore) -> Result<Self, JsError> {
        Ok(match v {
            SDKProofOfPossessionNotBefore::AsIssuedAt => WasmProofOfPossessionNotBefore {
                strategy: WasmProofOfPossessionNotBeforeStrategy::AsIssuedAt,
                fixed: None,
                delay: None,
                leeway: None,
            },
            SDKProofOfPossessionNotBefore::Fixed(t) => WasmProofOfPossessionNotBefore {
                strategy: WasmProofOfPossessionNotBeforeStrategy::Fixed,
                fixed: Some(t.unix_timestamp()),
                delay: None,
                leeway: None,
            },
            SDKProofOfPossessionNotBefore::Delay(d) => WasmProofOfPossessionNotBefore {
                strategy: WasmProofOfPossessionNotBeforeStrategy::Delay,
                fixed: None,
                delay: Some(d.whole_seconds()),
                leeway: None,
            },
            SDKProofOfPossessionNotBefore::Leeway(l) => WasmProofOfPossessionNotBefore {
                strategy: WasmProofOfPossessionNotBeforeStrategy::Leeway,
                fixed: None,
                delay: None,
                leeway: Some(l.whole_seconds()),
            },
        })
    }
}

// ===== ProofOfPossessionMetadata =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmProofOfPossessionMetadata {
    pub lifetime: Option<i64>, // seconds
    pub not_before: Option<WasmProofOfPossessionNotBefore>,
}

impl TryFrom<WasmProofOfPossessionMetadata> for ProofOfPossessionMetadata {
    type Error = JsError;

    fn try_from(v: WasmProofOfPossessionMetadata) -> Result<Self, JsError> {
        let lifetime = v
            .lifetime
            .map(Duration::seconds)
            .unwrap_or_else(|| Duration::minutes(DEFAULT_POP_LIFETIME_MINUTES));
        Ok(ProofOfPossessionMetadata {
            lifetime,
            not_before: v.not_before.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<ProofOfPossessionMetadata> for WasmProofOfPossessionMetadata {
    type Error = JsError;

    fn try_from(v: ProofOfPossessionMetadata) -> Result<Self, JsError> {
        Ok(WasmProofOfPossessionMetadata {
            lifetime: Some(v.lifetime.whole_seconds()),
            not_before: v.not_before.map(TryInto::try_into).transpose()?,
        })
    }
}

// ===== HolderMetadata =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmHolderMetadata {
    pub client_id: String,
    pub pop: WasmProofOfPossessionMetadata,
}

impl TryFrom<WasmHolderMetadata> for HolderMetadata {
    type Error = JsError;

    fn try_from(v: WasmHolderMetadata) -> Result<Self, JsError> {
        Ok(HolderMetadata {
            client_id: v.client_id,
            pop: v.pop.try_into()?,
        })
    }
}

// ===== HolderBinder =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmHolderBinder {
    pub nonce: String,
    pub verifier_id: String,
    pub response_uri: Option<String>,
}

impl From<WasmHolderBinder> for HolderBinder {
    fn from(v: WasmHolderBinder) -> Self {
        HolderBinder {
            nonce: Nonce::from_secret(v.nonce),
            verifier_id: v.verifier_id,
            response_uri: v.response_uri,
        }
    }
}

impl From<HolderBinder> for WasmHolderBinder {
    fn from(v: HolderBinder) -> Self {
        WasmHolderBinder {
            nonce: v.nonce.secret().to_string(),
            verifier_id: v.verifier_id,
            response_uri: v.response_uri,
        }
    }
}
