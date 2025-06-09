use crate::common::{Error, Result};
use crate::key_handle::WrappedKeyHandle;
use agent_sdk::did::universal::DIDResolver as ASDKDIDResolver;
use agent_sdk::did::{
    DIDBuf, DIDURLBuf, ResolutionError, ResolutionOptions, ResolutionOptionsMediaType,
    ResolutionOutput, SpruceDID, VerificationMethodMap, VerificationRelationshipType,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

pub type DIDDocMetadata = agent_sdk::did::DocumentMetadata;
pub type DIDMetadata = agent_sdk::did::ResolutionMetadata;

pub mod key;
pub mod universal_resolver;
pub mod web;

#[uniffi::remote(Enum)]
pub enum ResolutionOptionsMediaType {
    Json,
    JsonLd,
}

#[derive(uniffi::Record)]
pub struct DIDResolutionOptions {
    pub accept: Option<ResolutionOptionsMediaType>,
    pub parameters: Value,
}

impl TryFrom<ResolutionOptions> for DIDResolutionOptions {
    type Error = Error;
    fn try_from(value: ResolutionOptions) -> Result<Self> {
        Ok(Self {
            accept: value.accept,
            parameters: serde_json::to_value(value.parameters).map_err(|e| {
                Error::DIDResolution {
                    details: format!(
                        "Resolution options parameter parsing error: {:#?}",
                        e.to_string()
                    ),
                }
            })?,
        })
    }
}

#[uniffi::export(with_foreign)]
#[async_trait]
pub trait DIDResolver: Send + Sync {
    async fn resolve_representation(
        &self,
        did: String,
        options: DIDResolutionOptions,
    ) -> Result<DIDResolution>;

    fn method_name(&self) -> String;
}

pub struct WrappedDIDResolver(Arc<dyn DIDResolver>);
impl WrappedDIDResolver {
    pub fn new(inner: Arc<dyn DIDResolver>) -> Self {
        Self(inner)
    }
    pub fn inner(&self) -> Arc<dyn DIDResolver> {
        self.0.to_owned()
    }
}

#[async_trait]
impl ASDKDIDResolver for WrappedDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a SpruceDID,
        options: ResolutionOptions,
    ) -> std::result::Result<ResolutionOutput, ResolutionError> {
        let options = options
            .try_into()
            .map_err(|_| ResolutionError::InvalidOptions)?;

        self.inner()
            .resolve_representation(did.to_string(), options)
            .await
            .map_err(|e| ResolutionError::Internal(e.to_string()))?
            .try_into()
            .map_err(|_| ResolutionError::Internal("Could not resolve representation".to_string()))
    }

    fn method_name(&self) -> String {
        self.inner().method_name()
    }
}

#[uniffi::remote(Enum)]
pub enum VerificationRelationshipType {
    Authentication,
    Assertion,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(uniffi::Object)]
pub struct VerificationMethodKey {
    key: WrappedKeyHandle,
    verification_relationships: HashSet<VerificationRelationshipType>,
}

#[uniffi::export]
impl VerificationMethodKey {
    #[uniffi::constructor]
    pub fn new(kh: WrappedKeyHandle, verifications: Vec<VerificationRelationshipType>) -> Self {
        Self {
            key: kh,
            verification_relationships: HashSet::from_iter(verifications),
        }
    }
}

#[derive(uniffi::Record, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Verification method identifier.
    pub id: String,

    /// type [property](https://www.w3.org/TR/did-core/#dfn-did-urls) of a verification method map.
    /// Should be registered in [DID Specification
    /// registries - Verification method types](https://www.w3.org/TR/did-spec-registries/#verification-method-types).
    #[serde(rename = "type")]
    pub type_: String,

    /// [controller](https://w3c-ccg.github.io/ld-proofs/#controller) property of a verification
    /// method map.
    ///
    /// Not to be confused with the [controller](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document.
    pub controller: String,

    /// Verification methods properties.
    #[serde(flatten)]
    pub properties: HashMap<String, String>,
}

impl TryFrom<VerificationMethod> for VerificationMethodMap {
    type Error = Error;

    fn try_from(value: VerificationMethod) -> Result<Self> {
        let id = DIDURLBuf::from_str(&value.id).map_err(|err| Error::DIDResolution {
            details: err.to_string(),
        })?;
        let controller =
            DIDBuf::from_str(&value.controller).map_err(|err| Error::DIDResolution {
                details: err.to_string(),
            })?;

        let properties = value
            .properties
            .iter()
            .map(|(k, v)| serde_json::to_value(v).map(|val| (k.to_owned(), val)))
            .collect::<std::result::Result<_, _>>()
            .map_err(|err| Error::DIDResolution {
                details: err.to_string(),
            })?;

        Ok(VerificationMethodMap::new(
            id,
            value.type_,
            controller,
            properties,
        ))
    }
}

impl TryFrom<VerificationMethodMap> for VerificationMethod {
    type Error = Error;

    fn try_from(value: VerificationMethodMap) -> Result<Self> {
        let properties = value
            .properties
            .iter()
            .map(|(key, value)| {
                let result = match value {
                    Value::String(str) => Ok(str.to_owned()),
                    _ => serde_json::to_string(value),
                };

                result.map(|val| (key.to_owned(), val))
            })
            .collect::<std::result::Result<_, _>>()
            .map_err(|err| Error::DIDResolution {
                details: err.to_string(),
            })?;

        Ok(VerificationMethod {
            id: value.id.as_str().to_string(),
            type_: value.type_,
            controller: value.controller.as_str().to_string(),
            properties,
        })
    }
}

#[uniffi::remote(Record)]
pub struct DIDDocMetadata {
    pub deactivated: Option<bool>,
}

#[uniffi::remote(Record)]
pub struct DIDMetadata {
    pub content_type: Option<String>,
}

/// The result of a DID resolution.
#[derive(uniffi::Record, Debug)]
pub struct DIDResolution {
    // TODO: Use DID document structure instead of string
    /// The resolved DID Document
    pub document: String,
    /// Metadata related to the DID Document (e.g., deactivation status)
    pub document_metadata: DIDDocMetadata,
    /// Additional resolution metadata (e.g., content type)
    pub metadata: DIDMetadata,
}

impl TryFrom<ResolutionOutput> for DIDResolution {
    type Error = Error;

    fn try_from(value: ResolutionOutput) -> Result<Self> {
        let document =
            serde_json::to_string(&value.document).map_err(|err| Error::DIDResolution {
                details: err.to_string(),
            })?;

        Ok(DIDResolution {
            document,
            document_metadata: value.document_metadata,
            metadata: value.metadata,
        })
    }
}
impl TryFrom<DIDResolution> for ResolutionOutput {
    type Error = Error;

    fn try_from(value: DIDResolution) -> Result<Self> {
        let document =
            serde_json::from_str(&value.document).map_err(|err| Error::DIDResolution {
                details: err.to_string(),
            })?;

        Ok(ResolutionOutput {
            document,
            document_metadata: value.document_metadata,
            metadata: value.metadata,
        })
    }
}
