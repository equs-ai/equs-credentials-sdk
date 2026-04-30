use crate::did::didethr::types::{Address, Block};
use serde::{Deserialize, Serialize};
use ssi::dids::Document;
pub const DID_RESOLUTION_FORMAT: &str = "application/did+ld+json";

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DidResolutionError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum DidResolutionError {
    #[serde(rename = "invalidDid")]
    InvalidDid,
    #[serde(rename = "notFound")]
    NotFound,
    #[serde(rename = "representationNotSupported")]
    RepresentationNotSupported,
    #[serde(rename = "invalidDidUrl")]
    InvalidDidUrl,
    #[serde(rename = "methodNotSupported")]
    MethodNotSupported,
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_tag: Option<Block>,
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentWithMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<Document>,
    #[serde(default)]
    pub did_document_metadata: DidMetadata,
    #[serde(default)]
    pub did_resolution_metadata: DidResolutionMetadata,
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidRecord {
    pub document: Document,
    pub metadata: DidMetadata,
}
