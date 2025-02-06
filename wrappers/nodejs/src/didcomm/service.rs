use crate::didcomm::kms::DIDCommKms;
use crate::kms::{KeyHandleWrapper, NativeKms};
use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::didcomm::{DIDCommService, PackEncryptedOptions, UnpackOptions};
use napi::Error;
use napi_derive::napi;

#[napi(object)]
pub struct PackEncryptedResult {
    pub encrypted_msg: String,
    #[napi(ts_type = "PackEncryptedMetadata")]
    pub metadata: JsonObject,
}

#[napi(object)]
pub struct PackSignedResult {
    pub signed_msg: String,
    #[napi(ts_type = "PackSignedMetadata")]
    pub metadata: JsonObject,
}

#[napi(object)]
pub struct UnpackResult {
    #[napi(ts_type = "DIDCommMessage")]
    pub message: JsonObject,
    #[napi(ts_type = "UnpackMetadata")]
    pub metadata: JsonObject,
}

#[napi(js_name = "DIDCommService")]
pub struct JsDIDCommService(DIDCommService<DIDCommKms, KeyHandleWrapper>);

#[allow(clippy::new_without_default)]
#[napi]
impl JsDIDCommService {
    #[napi(constructor)]
    pub fn new(kms: &NativeKms) -> Self {
        let universal_resolver = UniversalResolver::default();
        let kms: DIDCommKms = kms.into();

        let inner_service = DIDCommService::new(kms, universal_resolver);

        JsDIDCommService(inner_service)
    }

    #[napi]
    pub async fn pack_plaintext(
        &self,
        #[napi(ts_arg_type = "DIDCommMessage")] message: JsonObject,
    ) -> napi::Result<String> {
        self.0
            .pack_plaintext(&from_json_object(message)?)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))
    }

    #[napi]
    pub async fn pack_signed(
        &self,
        #[napi(ts_arg_type = "DIDCommMessage")] message: JsonObject,
        sign_by: String,
    ) -> napi::Result<PackSignedResult> {
        let (signed_msg, metadata) = self
            .0
            .pack_signed(&from_json_object(message)?, &sign_by)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(PackSignedResult {
            signed_msg,
            metadata: to_json_object(metadata)?,
        })
    }

    #[napi]
    pub async fn pack_encrypted(
        &self,
        #[napi(ts_arg_type = "DIDCommMessage")] message: JsonObject,
        to: String,
        from: Option<String>,
        sign_by: Option<String>,
        #[napi(ts_arg_type = "PackEncryptedOptions | undefined")] options: Option<JsonObject>,
    ) -> napi::Result<PackEncryptedResult> {
        let options = match options {
            Some(options) => from_json_object(options)?,
            None => PackEncryptedOptions::default(),
        };

        let (encrypted_msg, metadata) = self
            .0
            .pack_encrypted(
                &from_json_object(message)?,
                &to,
                from.as_deref(),
                sign_by.as_deref(),
                &options,
            )
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(PackEncryptedResult {
            encrypted_msg,
            metadata: to_json_object(metadata)?,
        })
    }

    #[napi]
    pub async fn unpack(
        &self,
        msg: String,
        #[napi(ts_arg_type = "UnpackOptions | undefined")] options: Option<JsonObject>,
    ) -> napi::Result<UnpackResult> {
        let options = match options {
            Some(options) => from_json_object(options)?,
            None => UnpackOptions::default(),
        };

        let (message, metadata) = self
            .0
            .unpack(&msg, &options)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(UnpackResult {
            message: to_json_object(message)?,
            metadata: to_json_object(metadata)?,
        })
    }
}
