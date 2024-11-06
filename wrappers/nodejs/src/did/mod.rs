mod key;
mod web;

use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{
    DIDResolver as ASDKDIDResolver, Resolution, ResolutionMetadata, ResolutionVerificationSnafu,
    ResolveOptions, VerificationMethodMap,
};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::{Error, Result};
use napi_derive::napi;

#[napi(object, js_name = "ResolveOptions")]
pub struct JsResolveOptions {
    pub input: JsonObject,
}
impl TryFrom<JsResolveOptions> for ResolveOptions {
    type Error = Error;

    fn try_from(value: JsResolveOptions) -> Result<Self> {
        Ok(Self {
            input: from_json_object(value.input)?,
        })
    }
}
impl TryFrom<ResolveOptions> for JsResolveOptions {
    type Error = Error;

    fn try_from(value: ResolveOptions) -> Result<Self> {
        Ok(Self {
            input: to_json_object(value.input)?,
        })
    }
}

#[napi(object, js_name = "Resolution")]
pub struct JsResolution {
    pub metadata: JsonObject,
    pub doc: Option<JsonObject>,
    pub doc_metadata: Option<JsonObject>,
}

impl TryFrom<JsResolution> for Resolution {
    type Error = Error;
    fn try_from(value: JsResolution) -> Result<Self> {
        Ok(Self {
            metadata: from_json_object(value.metadata)?,
            doc: value.doc.map(from_json_object).transpose()?,
            doc_metadata: value.doc_metadata.map(from_json_object).transpose()?,
        })
    }
}
impl TryFrom<Resolution> for JsResolution {
    type Error = Error;
    fn try_from(value: Resolution) -> Result<Self> {
        Ok(Self {
            metadata: to_json_object(value.metadata)?,
            doc: value.doc.map(to_json_object).transpose()?,
            doc_metadata: value.doc_metadata.map(to_json_object).transpose()?,
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
