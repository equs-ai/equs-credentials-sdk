use crate::common::{Error, Result, Url};
use crate::vc::core::status_formats::StatusListFormat;
use crate::vc::{Alg, VCFormat};
use agent_sdk::vc::Presentation as ASDKPresentation;
pub use agent_sdk::vc::StatusList;
use agent_sdk::vc::VCStatusesData as ASDKVCStatusesData;
use agent_sdk::vc::core::{
    CredentialDefinition as ASDKCredentialDefinition, CredentialOffer as ASDKCredentialOffer,
    CredentialOfferContent as ASDKCredentialOfferContent, IssuerMetadata as ASDKIssuerMetadata,
    KeyMetadata as ASDKKeyMetadata, ProofOfPossessionMetadata as ASDKPoPMetadata,
    StatusIssuerMetadata as ASDKStatusIssuerMetadata,
    StatusListDefinition as ASDKStatusListDefinition,
};
pub use agent_sdk::vc::core::{
    CredentialDefinitionData, CredentialOfferData, CredentialRequest, CredentialRequestData,
    CredentialStatusInfo, Display, HolderBinder, HolderMetadata, IssuerMetadataData, PopFormat,
    PresentationInput, PresentationRestriction, PresentationRestrictionValue, Proof,
};
use agent_sdk::vc::status_formats::status_list_token_jwt::{
    VCStatus as SltVcStatus, VCStatuses as ASDKVcStatuses,
};
use std::collections::HashMap;
use time::Duration;
use tracing;
use uniffi::{custom_type, deps::anyhow};

#[uniffi::remote(Record)]
pub struct Proof {
    pub format: String,
    pub proof: String,
}

#[uniffi::remote(Record)]
pub struct CredentialRequestData {
    /// `Duration` is bridged to `i64` seconds at the FFI boundary.
    pub proof_tolerance: Option<Duration>,
}

#[uniffi::remote(Record)]
pub struct Display {}

#[uniffi::remote(Record)]
pub struct IssuerMetadataData {}

#[uniffi::remote(Record)]
pub struct CredentialOfferData {}

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum PopFormat {
    Jwt,
    DiVp,
}

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum CredentialDefinitionData {
    SdJwt {
        vct: String,
        disclosures: Vec<String>,
        lifetime: Option<Duration>,
    },
    Ldp {
        contexts: Vec<String>,
        vc_types: Vec<String>,
        credential_id: Option<String>,
        lifetime: Option<Duration>,
    },
}

#[uniffi::remote(Enum)]
pub enum CredentialStatusInfo {
    TokenStatusList { idx: u32, uri: Url },
    BitstringStatusList,
}

/// Entry in the typed projection of the SDK's
/// `HashMap<pop::Format, Vec<Alg>>` — UniFFI requires `String` map keys, so the
/// HashMap is transposed into a list at the FFI boundary.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct SupportedProofEntry {
    pub format: PopFormat,
    pub algs: Vec<Alg>,
}

/// Entry in the typed projection of the SDK's `HashMap<usize, u8>` — same
/// reason: non-`String` map keys can't ride UniFFI's `HashMap`.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct StatusEntry {
    pub index: u32,
    pub status: u8,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct CredentialDefinition {
    pub cred_def_id: String,
    pub format: VCFormat,
    pub claims: HashMap<String, Display>,
    pub supported_proofs: Option<Vec<SupportedProofEntry>>,
    pub supported_signing_algs: Option<Vec<Alg>>,
    pub display: Option<Display>,
    pub protocol_data: Option<CredentialDefinitionData>,
    pub key_metadata: ASDKKeyMetadata,
}

fn supported_proofs_to_sdk(entries: Vec<SupportedProofEntry>) -> HashMap<PopFormat, Vec<Alg>> {
    entries.into_iter().map(|e| (e.format, e.algs)).collect()
}

fn supported_proofs_from_sdk(map: HashMap<PopFormat, Vec<Alg>>) -> Vec<SupportedProofEntry> {
    map.into_iter()
        .map(|(format, algs)| SupportedProofEntry { format, algs })
        .collect()
}

impl From<CredentialDefinition> for ASDKCredentialDefinition {
    fn from(v: CredentialDefinition) -> Self {
        ASDKCredentialDefinition {
            cred_def_id: v.cred_def_id,
            format: v.format,
            claims: v.claims,
            supported_proofs: v.supported_proofs.map(supported_proofs_to_sdk),
            supported_signing_algs: v.supported_signing_algs,
            display: v.display,
            protocol_data: v.protocol_data,
            key_metadata: v.key_metadata,
        }
    }
}

impl From<ASDKCredentialDefinition> for CredentialDefinition {
    fn from(v: ASDKCredentialDefinition) -> Self {
        CredentialDefinition {
            cred_def_id: v.cred_def_id,
            format: v.format,
            claims: v.claims,
            supported_proofs: v.supported_proofs.map(supported_proofs_from_sdk),
            supported_signing_algs: v.supported_signing_algs,
            display: v.display,
            protocol_data: v.protocol_data,
            key_metadata: v.key_metadata,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct IssuerMetadata {
    pub issuer_id: String,
    pub cred_defs: Vec<CredentialDefinition>,
    pub protocol_data: Option<IssuerMetadataData>,
}

impl From<IssuerMetadata> for ASDKIssuerMetadata {
    fn from(v: IssuerMetadata) -> Self {
        ASDKIssuerMetadata {
            issuer_id: v.issuer_id,
            cred_defs: v.cred_defs.into_iter().map(Into::into).collect(),
            protocol_data: v.protocol_data,
        }
    }
}

impl From<ASDKIssuerMetadata> for IssuerMetadata {
    fn from(v: ASDKIssuerMetadata) -> Self {
        IssuerMetadata {
            issuer_id: v.issuer_id,
            cred_defs: v.cred_defs.into_iter().map(Into::into).collect(),
            protocol_data: v.protocol_data,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(uniffi::Enum, Clone, Debug)]
pub enum CredentialOfferContent {
    CredDef(CredentialDefinition),
    SupportedProofs(Option<Vec<SupportedProofEntry>>),
}

impl From<CredentialOfferContent> for ASDKCredentialOfferContent {
    fn from(v: CredentialOfferContent) -> Self {
        match v {
            CredentialOfferContent::CredDef(cd) => ASDKCredentialOfferContent::CredDef(cd.into()),
            CredentialOfferContent::SupportedProofs(entries) => {
                ASDKCredentialOfferContent::SupportedProofs(entries.map(supported_proofs_to_sdk))
            }
        }
    }
}

impl From<ASDKCredentialOfferContent> for CredentialOfferContent {
    fn from(v: ASDKCredentialOfferContent) -> Self {
        match v {
            ASDKCredentialOfferContent::CredDef(cd) => CredentialOfferContent::CredDef(cd.into()),
            ASDKCredentialOfferContent::SupportedProofs(map) => {
                CredentialOfferContent::SupportedProofs(map.map(supported_proofs_from_sdk))
            }
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct CredentialOffer {
    pub cred_offer_id: Option<String>,
    pub issuer_id: String,
    pub cred_def_id: String,
    pub content: CredentialOfferContent,
    pub protocol_data: Option<CredentialOfferData>,
}

impl From<CredentialOffer> for ASDKCredentialOffer {
    fn from(v: CredentialOffer) -> Self {
        ASDKCredentialOffer {
            cred_offer_id: v.cred_offer_id,
            issuer_id: v.issuer_id,
            cred_def_id: v.cred_def_id,
            content: v.content.into(),
            protocol_data: v.protocol_data,
        }
    }
}

impl From<ASDKCredentialOffer> for CredentialOffer {
    fn from(v: ASDKCredentialOffer) -> Self {
        CredentialOffer {
            cred_offer_id: v.cred_offer_id,
            issuer_id: v.issuer_id,
            cred_def_id: v.cred_def_id,
            content: v.content.into(),
            protocol_data: v.protocol_data,
        }
    }
}

#[uniffi::remote(Record)]
pub struct CredentialRequest {
    pub cred_def_id: String,
    pub cred_offer_id: Option<String>,
    pub proof: Proof,
    pub protocol_data: Option<CredentialRequestData>,
}

#[uniffi::remote(Record)]
pub struct HolderMetadata {
    pub client_id: String,
    pub pop: ASDKPoPMetadata,
}

#[uniffi::remote(Record)]
pub struct HolderBinder {
    /// `Nonce` is bridged to `String` via the custom_type in `crate::crypto`;
    /// the Rust field keeps `Nonce` to preserve zeroize-on-drop.
    pub nonce: crate::crypto::Nonce,
    pub verifier_id: String,
}

#[uniffi::remote(Enum)]
pub enum PresentationRestrictionValue {
    Const(String),
    Pattern(String),
    /// SDK uses `Vec<SetOfValues>` where `SetOfValues = Vec<String>` is a
    /// private alias; expanded inline so the macro resolves the type.
    ArrayOfValues(Vec<Vec<String>>),
}

#[uniffi::remote(Record)]
pub struct PresentationRestriction {
    pub fields: Vec<String>,
    pub value: Option<PresentationRestrictionValue>,
    pub optional: bool,
}

#[uniffi::remote(Record)]
pub struct PresentationInput {
    pub id: String,
    pub format: Option<String>,
    pub restrictions: Vec<PresentationRestriction>,
}

#[non_exhaustive]
#[derive(uniffi::Enum, Clone, Debug)]
pub enum VCStatusesData {
    StatusListToken(Vec<StatusEntry>),
    BitstringStatusList,
}

impl TryFrom<VCStatusesData> for ASDKVCStatusesData {
    type Error = Error;
    fn try_from(v: VCStatusesData) -> Result<Self> {
        Ok(match v {
            VCStatusesData::StatusListToken(entries) => {
                let mut vc_statuses = ASDKVcStatuses::new();
                for e in entries {
                    vc_statuses.set(e.index as usize, SltVcStatus::from(e.status));
                }
                ASDKVCStatusesData::StatusListToken(vc_statuses)
            }
            VCStatusesData::BitstringStatusList => ASDKVCStatusesData::BitstringStatusList,
        })
    }
}

impl TryFrom<ASDKVCStatusesData> for VCStatusesData {
    type Error = Error;
    fn try_from(v: ASDKVCStatusesData) -> Result<Self> {
        Ok(match v {
            ASDKVCStatusesData::StatusListToken(s) => {
                let entries = s
                    .statuses()
                    .iter()
                    .map(|(&index, &status)| StatusEntry {
                        index: index as u32,
                        status,
                    })
                    .collect();
                VCStatusesData::StatusListToken(entries)
            }
            ASDKVCStatusesData::BitstringStatusList => VCStatusesData::BitstringStatusList,
            _ => {
                return Err(Error::Core(
                    "Unsupported VCStatusesData variant".to_string(),
                ));
            }
        })
    }
}

#[uniffi::remote(Enum)]
pub enum StatusList {
    StatusListTokenJwt(String),
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct StatusListDefinition {
    pub id: String,
    pub format: StatusListFormat,
    pub key_metadata: ASDKKeyMetadata,
}

impl TryFrom<StatusListDefinition> for ASDKStatusListDefinition {
    type Error = Error;
    fn try_from(v: StatusListDefinition) -> Result<Self> {
        Ok(ASDKStatusListDefinition {
            id: v.id,
            format: v.format.try_into()?,
            key_metadata: v.key_metadata,
        })
    }
}
impl TryFrom<ASDKStatusListDefinition> for StatusListDefinition {
    type Error = Error;
    fn try_from(v: ASDKStatusListDefinition) -> Result<Self> {
        Ok(StatusListDefinition {
            id: v.id,
            format: v.format.try_into()?,
            key_metadata: v.key_metadata,
        })
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct StatusIssuerMetadata {
    pub issuer_id: String,
    pub supported_status_lists: Vec<StatusListDefinition>,
}

impl TryFrom<StatusIssuerMetadata> for ASDKStatusIssuerMetadata {
    type Error = Error;
    fn try_from(v: StatusIssuerMetadata) -> Result<Self> {
        Ok(ASDKStatusIssuerMetadata {
            issuer_id: v.issuer_id,
            supported_status_lists: v
                .supported_status_lists
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}
impl TryFrom<ASDKStatusIssuerMetadata> for StatusIssuerMetadata {
    type Error = Error;
    fn try_from(v: ASDKStatusIssuerMetadata) -> Result<Self> {
        Ok(StatusIssuerMetadata {
            issuer_id: v.issuer_id,
            supported_status_lists: v
                .supported_status_lists
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

/// `JwtVp`/`LdpVp` carry JSON-serialized SDK payloads; `SdJwtVp` carries the
/// SD-JWT compact string verbatim; `MsoMdocVp` carries a JSON-serialized
/// `mso_mdoc::Presentation`. Bridged to `ASDKPresentation` via the
/// `custom_type!` declaration below.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum Presentation {
    JwtVp(String),
    LdpVp(String),
    SdJwtVp(String),
    MsoMdocVp(String),
}

impl TryFrom<ASDKPresentation> for Presentation {
    type Error = Error;
    fn try_from(value: ASDKPresentation) -> Result<Self> {
        Ok(match value {
            ASDKPresentation::JwtVp(v) => Presentation::JwtVp(
                serde_json::to_string(&v).map_err(|e| Error::Core(e.to_string()))?,
            ),
            ASDKPresentation::LdpVp(v) => Presentation::LdpVp(
                serde_json::to_string(&v).map_err(|e| Error::Core(e.to_string()))?,
            ),
            ASDKPresentation::SdJwtVp(v) => Presentation::SdJwtVp(v),
            ASDKPresentation::MsoMdoc(v) => Presentation::MsoMdocVp(
                serde_json::to_string(&v).map_err(|e| Error::Core(e.to_string()))?,
            ),
            _ => {
                return Err(Error::Core("Unsupported presentation format".to_string()));
            }
        })
    }
}

impl TryFrom<Presentation> for ASDKPresentation {
    type Error = Error;
    fn try_from(value: Presentation) -> Result<Self> {
        Ok(match value {
            Presentation::JwtVp(payload) => ASDKPresentation::JwtVp(
                serde_json::from_str(&payload).map_err(|e| Error::Core(e.to_string()))?,
            ),
            Presentation::LdpVp(payload) => ASDKPresentation::LdpVp(
                serde_json::from_str(&payload).map_err(|e| Error::Core(e.to_string()))?,
            ),
            Presentation::SdJwtVp(payload) => ASDKPresentation::SdJwtVp(payload),
            Presentation::MsoMdocVp(payload) => ASDKPresentation::MsoMdoc(
                serde_json::from_str(&payload).map_err(|e| Error::Core(e.to_string()))?,
            ),
        })
    }
}

custom_type!(ASDKPresentation, Presentation, {
    remote,
    lower: |p| {
        p.try_into().unwrap_or_else(|e: Error| {
            // Only reachable when the SDK adds a new #[non_exhaustive] Presentation variant
            // that this wrapper hasn't been updated for. Log rather than panic across FFI.
            tracing::error!("Presentation::lower: unsupported variant, returning poison sentinel: {e}");
            Presentation::JwtVp(String::new())
        })
    },
    try_lift: |pd| pd.try_into().map_err(anyhow::Error::msg),
});
