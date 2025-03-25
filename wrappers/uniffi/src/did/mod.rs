use crate::common::{Error, Result};
use agent_sdk::did::{DIDBuf, DIDURLBuf, ResolutionOutput, VerificationMethodMap};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

pub type DIDDocMetadata = agent_sdk::did::DocumentMetadata;
pub type DIDMetadata = agent_sdk::did::ResolutionMetadata;

pub mod universal_resolver;

#[derive(uniffi::Record)]
pub struct VerificationMethod {
    /// Verification method identifier.
    pub id: String,

    /// type [property](https://www.w3.org/TR/did-core/#dfn-did-urls) of a verification method map.
    /// Should be registered in [DID Specification
    /// registries - Verification method types](https://www.w3.org/TR/did-spec-registries/#verification-method-types).
    pub type_: String,

    /// [controller](https://w3c-ccg.github.io/ld-proofs/#controller) property of a verification
    /// method map.
    ///
    /// Not to be confused with the [controller](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document.
    pub controller: String,

    /// Verification methods properties.
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
#[derive(uniffi::Record)]
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
