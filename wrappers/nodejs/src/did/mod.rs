mod key;
mod peer;
mod web;
mod webvh;

use crate::http::ReqwestHttpClient;
use crate::kms::JsKeyHandle;
use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use async_trait::async_trait;
use equs_sdk::did::universal::{DIDResolver, UniversalResolver};
use equs_sdk::did::{
    DIDBuf, DIDResolver as EqusSdkDIDResolver, DocumentMetadata, ResolutionError,
    ResolutionMetadata, ResolutionOptions, ResolutionOutput, SpruceDID,
};
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::{Error, Result};
use napi_derive::napi;
use std::str::FromStr;
use std::sync::Arc;

#[napi(js_name = "VerificationRelationshipType")]
pub enum JsVerificationRelationshipType {
    Authentication,
    Assertion,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[napi(js_name = "VerificationMethodKey")]
pub struct JsVerificationMethodKey {
    key: JsKeyHandle,
    verification_relationships: Vec<JsVerificationRelationshipType>,
}

#[napi]
impl JsVerificationMethodKey {
    #[napi(constructor)]
    pub fn new(
        key: JsKeyHandle,
        verification_relationships: Vec<JsVerificationRelationshipType>,
    ) -> Self {
        Self {
            key,
            verification_relationships,
        }
    }
}

#[napi(js_name = "_UniversalDIDResolver")]
pub struct JsUniversalDIDResolver {
    inner: UniversalResolver,
}

#[napi]
impl JsUniversalDIDResolver {
    #[allow(clippy::new_without_default)]
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: UniversalResolver::default(),
        }
    }

    #[napi(factory, ts_return_type = "_UniversalDIDResolver")]
    pub fn with_http_client(http_client: &ReqwestHttpClient) -> Self {
        Self {
            inner: UniversalResolver::new(Arc::new(http_client.inner())),
        }
    }

    #[napi(ts_return_type = "Promise<DIDVerificationMethod>")]
    pub async fn resolve_verification_method(&self, did: String) -> Result<JsonObject> {
        self.inner
            .resolve_into_any_verification_method(
                &DIDBuf::from_str(&did).map_err(|err| Error::from_reason(err.to_string()))?,
            )
            .await
            .map_err(|err| Error::from_reason(err.to_string()))
            .and_then(to_json_object)
    }

    #[napi(ts_return_type = "Promise<DIDResolution>")]
    pub async fn resolve(&self, did: String) -> Result<JsonObject> {
        self.inner
            .resolve(&DIDBuf::from_str(&did).map_err(|err| Error::from_reason(err.to_string()))?)
            .await
            .map_err(|err| Error::from_reason(err.to_string()))
            .map(|output| {
                serde_json::json!({
                    "document": output.document,
                    "metadata": output.metadata,
                    "document_metadata": output.document_metadata,
                })
            })
            .and_then(to_json_object)
    }

    #[napi]
    pub fn add_resolver(
        &mut self,
        #[napi(ts_arg_type = "DIDResolver")] did_resolver: JsDIDResolver,
    ) -> Result<()> {
        self.inner
            .add_resolver(did_resolver)
            .map_err(|err| Error::from_reason(err.to_string()))?;
        Ok(())
    }
}

impl From<&JsUniversalDIDResolver> for UniversalResolver {
    fn from(value: &JsUniversalDIDResolver) -> UniversalResolver {
        value.inner.clone()
    }
}

#[napi(js_name = "ResolutionOptions")]
pub struct JsResolutionOptions {
    #[napi(ts_type = "'application/did+json' | 'application/did+ld+json'")]
    pub accept: Option<String>,

    #[napi(ts_type = "ResolutionOptionsParameter")]
    pub parameters: JsonObject,
}

impl TryFrom<ResolutionOptions> for JsResolutionOptions {
    type Error = Error;
    fn try_from(value: ResolutionOptions) -> Result<Self> {
        Ok(Self {
            accept: value.accept.map(|value| value.into()),
            parameters: to_json_object(value.parameters)?,
        })
    }
}

#[derive(Clone)]
#[napi(js_name = "DIDDocMetadata", object)]
#[derive(Debug)]
pub struct JsDocumentMetadata {
    pub deactivated: Option<bool>,
}
impl From<DocumentMetadata> for JsDocumentMetadata {
    fn from(value: DocumentMetadata) -> Self {
        Self {
            deactivated: value.deactivated,
        }
    }
}
impl From<JsDocumentMetadata> for DocumentMetadata {
    fn from(value: JsDocumentMetadata) -> Self {
        Self {
            deactivated: value.deactivated,
        }
    }
}

#[derive(Clone)]
#[napi(js_name = "DIDMetadata", object)]
#[derive(Debug)]
pub struct JsResolutionMetadata {
    pub content_type: Option<String>,
}
impl From<ResolutionMetadata> for JsResolutionMetadata {
    fn from(value: ResolutionMetadata) -> Self {
        Self {
            content_type: value.content_type,
        }
    }
}
impl From<JsResolutionMetadata> for ResolutionMetadata {
    fn from(value: JsResolutionMetadata) -> Self {
        Self {
            content_type: value.content_type,
        }
    }
}

#[derive(Clone)]
#[napi(js_name = "DIDResolution", object)]
#[derive(Debug)]
pub struct JsResolutionOutput {
    #[napi(ts_type = "DIDDocument")]
    pub document: JsonObject,
    #[napi(js_name = "document_metadata")]
    pub document_metadata: JsDocumentMetadata,
    pub metadata: JsResolutionMetadata,
}
impl TryFrom<ResolutionOutput> for JsResolutionOutput {
    type Error = Error;
    fn try_from(value: ResolutionOutput) -> Result<Self> {
        Ok(Self {
            document: to_json_object(value.document)?,
            document_metadata: value.document_metadata.into(),
            metadata: value.metadata.into(),
        })
    }
}
impl TryFrom<JsResolutionOutput> for ResolutionOutput {
    type Error = Error;
    fn try_from(value: JsResolutionOutput) -> Result<Self> {
        Ok(Self {
            document: from_json_object(value.document)?,
            document_metadata: value.document_metadata.into(),
            metadata: value.metadata.into(),
        })
    }
}

#[derive(Clone)]
#[napi(js_name = "DIDResolver", object, object_to_js = false)]
pub struct JsDIDResolver {
    #[napi(
        ts_type = "(did: `did:${string}:${string}`, options: ResolutionOptions) => Promise<DIDResolution>"
    )]
    pub resolve_representation:
        ThreadsafeFunction<(String, JsResolutionOptions), ErrorStrategy::Fatal>,

    pub method_name: String,
}

#[async_trait]
impl DIDResolver for JsDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a SpruceDID,
        options: ResolutionOptions,
    ) -> std::result::Result<ResolutionOutput, ResolutionError> {
        let did = did.to_string();
        let options = options
            .try_into()
            .map_err(|_| ResolutionError::InvalidOptions)?;

        let promise: Promise<JsResolutionOutput> = self
            .resolve_representation
            .call_async((did, options))
            .await
            .map_err(|err| ResolutionError::Internal(err.to_string()))?;

        let output = promise.await;

        output
            .and_then(|result| result.try_into())
            .map_err(|err| ResolutionError::Internal(err.to_string()))
    }

    fn method_name(&self) -> String {
        self.method_name.to_owned()
    }
}
