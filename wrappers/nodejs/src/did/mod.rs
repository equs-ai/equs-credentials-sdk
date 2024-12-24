mod key;
mod web;

use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{
    DIDResolver as ASDKDIDResolver, DocumentMetadata, Metadata, Resolution,
    ResolutionInputMetadata, ResolutionMetadata, ResolutionVerificationSnafu, ResolveOptions,
    VerificationMethodMap,
};
use async_trait::async_trait;
use chrono::DateTime;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::{Error, Result};
use napi_derive::napi;
use std::collections::HashMap;

fn json_value_to_metadata(value: Option<JsonObject>) -> Result<Option<HashMap<String, Metadata>>> {
    let result = value
        .map(serde_json::Value::Object)
        .map(serde_json::from_value)
        .transpose()?;

    Ok(result)
}

fn metadata_to_json_value(value: Option<HashMap<String, Metadata>>) -> Result<Option<JsonObject>> {
    let result = value
        .map(serde_json::to_value)
        .transpose()?
        .map(serde_json::from_value)
        .transpose()?;

    Ok(result)
}

#[napi(object, js_name = "ResolutionInputMetadata")]
pub struct JsResolutionInputMetadata {
    pub accept: Option<String>,
    pub version_id: Option<String>,
    pub version_time: Option<String>,
    pub no_cache: Option<bool>,
    pub property_set: Option<JsonObject>,
}

impl TryFrom<JsResolutionInputMetadata> for ResolutionInputMetadata {
    type Error = Error;

    fn try_from(value: JsResolutionInputMetadata) -> Result<Self> {
        Ok(Self {
            accept: value.accept,
            version_id: value.version_id,
            version_time: value.version_time,
            no_cache: value.no_cache,
            property_set: json_value_to_metadata(value.property_set)?,
        })
    }
}
impl TryFrom<ResolutionInputMetadata> for JsResolutionInputMetadata {
    type Error = Error;

    fn try_from(value: ResolutionInputMetadata) -> Result<Self> {
        Ok(Self {
            accept: value.accept,
            version_id: value.version_id,
            version_time: value.version_time,
            no_cache: value.no_cache,
            property_set: metadata_to_json_value(value.property_set)?,
        })
    }
}

#[napi(object, js_name = "ResolveOptions")]
pub struct JsResolveOptions {
    pub input: JsResolutionInputMetadata,
}

impl TryFrom<JsResolveOptions> for ResolveOptions {
    type Error = Error;

    fn try_from(value: JsResolveOptions) -> Result<Self> {
        Ok(Self {
            input: value.input.try_into()?,
        })
    }
}
impl TryFrom<ResolveOptions> for JsResolveOptions {
    type Error = Error;

    fn try_from(value: ResolveOptions) -> Result<Self> {
        Ok(Self {
            input: value.input.try_into()?,
        })
    }
}

#[napi(object, js_name = "ResolutionMetadata")]
pub struct JsResolutionMetadata {
    pub error: Option<String>,
    pub content_type: Option<String>,
    pub property_set: Option<JsonObject>,
}

impl TryFrom<JsResolutionMetadata> for ResolutionMetadata {
    type Error = Error;

    fn try_from(value: JsResolutionMetadata) -> Result<Self> {
        Ok(Self {
            error: value.error,
            content_type: value.content_type,
            property_set: json_value_to_metadata(value.property_set)?,
        })
    }
}
impl TryFrom<ResolutionMetadata> for JsResolutionMetadata {
    type Error = Error;

    fn try_from(value: ResolutionMetadata) -> Result<Self> {
        Ok(Self {
            error: value.error,
            content_type: value.content_type,
            property_set: metadata_to_json_value(value.property_set)?,
        })
    }
}

#[napi(object, js_name = "DocumentMetadata")]
pub struct JsDocumentMetadata {
    pub created: Option<i64>,
    pub updated: Option<i64>,
    pub deactivated: Option<bool>,
    pub property_set: Option<JsonObject>,
}

impl TryFrom<JsDocumentMetadata> for DocumentMetadata {
    type Error = Error;

    fn try_from(value: JsDocumentMetadata) -> Result<Self> {
        Ok(Self {
            created: value
                .created
                .map(DateTime::from_timestamp_millis)
                .ok_or_else(|| Error::from_reason("Invalid timestamp"))?,
            updated: value
                .updated
                .map(DateTime::from_timestamp_millis)
                .ok_or_else(|| Error::from_reason("Invalid timestamp"))?,
            deactivated: value.deactivated,
            property_set: json_value_to_metadata(value.property_set)?,
        })
    }
}
impl TryFrom<DocumentMetadata> for JsDocumentMetadata {
    type Error = Error;

    fn try_from(value: DocumentMetadata) -> Result<Self> {
        Ok(Self {
            created: value.created.map(|d| d.timestamp_millis()),
            updated: value.updated.map(|d| d.timestamp_millis()),
            deactivated: value.deactivated,
            property_set: metadata_to_json_value(value.property_set)?,
        })
    }
}

#[napi(object, js_name = "Resolution")]
pub struct JsResolution {
    pub metadata: JsResolutionMetadata,
    pub doc_metadata: Option<JsDocumentMetadata>,
    pub doc: Option<JsonObject>,
}

impl TryFrom<JsResolution> for Resolution {
    type Error = Error;
    fn try_from(value: JsResolution) -> Result<Self> {
        Ok(Self {
            metadata: value.metadata.try_into()?,
            doc_metadata: value.doc_metadata.map(|doc| doc.try_into()).transpose()?,
            doc: value.doc.map(from_json_object).transpose()?,
        })
    }
}
impl TryFrom<Resolution> for JsResolution {
    type Error = Error;
    fn try_from(value: Resolution) -> Result<Self> {
        Ok(Self {
            metadata: value.metadata.try_into()?,
            doc_metadata: value.doc_metadata.map(|doc| doc.try_into()).transpose()?,
            doc: value.doc.map(to_json_object).transpose()?,
        })
    }
}

// TODO! Not possible to expose due to trait! Need to be implemented after ASDKDIDResolver trait changes (to_spruce_resolver)
// #[napi(js_name = "DIDResolver", object, object_to_js = false)]
pub struct JsDIDResolver {
    // #[napi(ts_type = "(did: string, options: ResolveOptions) => Promise<Resolution>")]
    pub _resolve: ThreadsafeFunction<(String, JsResolveOptions), ErrorStrategy::Fatal>,
    // #[napi(ts_type = "(did_url: string) => Promise<Record<string, any>>")]
    pub _resolve_verification_method: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
}

#[async_trait]
impl ASDKDIDResolver for JsDIDResolver {
    async fn resolve(&self, did: &str, options: ResolveOptions) -> Resolution {
        let options = options.try_into();

        let result = match options {
            Ok(options) => {
                self._resolve
                    .call_async::<Promise<JsResolution>>((did.to_owned(), options))
                    .await
            }
            Err(error) => Err(error),
        };
        let result = match result {
            Ok(value) => value.await.and_then(|v| v.try_into()),
            Err(error) => Err(error),
        };

        result.unwrap_or_else(|error| Resolution {
            metadata: ResolutionMetadata::from_error(&error.to_string()),
            doc: None,
            doc_metadata: None,
        })
    }

    async fn resolve_verification_method(
        &self,
        did_url: &str,
    ) -> agent_sdk::did::Result<VerificationMethodMap> {
        let result = self
            ._resolve_verification_method
            .call_async::<Promise<JsonObject>>(did_url.to_owned())
            .await
            .map_err(|e| {
                ResolutionVerificationSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .await
            .map_err(|e| {
                ResolutionVerificationSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        from_json_object(result).map_err(|e| {
            ResolutionVerificationSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }

    fn as_spruce_resolver(&self) -> &dyn agent_sdk::did::SpruceResolver {
        unreachable!()
    }
}

#[napi]
pub struct NativeDIDResolver(Box<dyn ASDKDIDResolver>);

#[napi]
impl NativeDIDResolver {
    #[napi]
    pub async fn resolve(&self, did: String, options: JsResolveOptions) -> Result<JsResolution> {
        let result = self.0.resolve(&did, options.try_into()?).await;

        result.try_into()
    }
    #[napi]
    pub async fn resolve_verification_method(&self, did_url: String) -> Result<JsonObject> {
        self.0
            .resolve_verification_method(&did_url)
            .await
            .map_err(|err| Error::from_reason(err.to_string()))
            .and_then(to_json_object)
    }
}

#[allow(unused)]
#[napi]
pub fn create_universal_did_resolver() -> Result<NativeDIDResolver> {
    let did = UniversalResolver::new();

    Ok(NativeDIDResolver(Box::new(did)))
}
