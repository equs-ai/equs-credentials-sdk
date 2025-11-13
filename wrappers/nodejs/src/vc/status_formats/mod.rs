use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::vc::TslVcStatus as AsdkTslVcStatus;
use agent_sdk::vc::status_formats::StatusListFormat;
use agent_sdk::vc::status_formats::status_list_token_jwt::VCStatus;
use napi::Error;
use napi_derive::napi;
use strum_macros::Display;

#[napi(js_name = "StatusListFormatFmt")]
pub enum JsStatusListFormatFmt {
    StatusListTokenJwt,
    StatusListTokenCwt,
}

#[napi(js_name = "StatusListFormat", object)]
pub struct JsStatusListFormat {
    pub format: JsStatusListFormatFmt,
    pub payload: JsonObject,
}

impl TryFrom<StatusListFormat> for JsStatusListFormat {
    type Error = Error;

    fn try_from(value: StatusListFormat) -> Result<Self, Error> {
        match value {
            StatusListFormat::StatusListTokenJwt(sl_metadata) => Ok(JsStatusListFormat {
                format: JsStatusListFormatFmt::StatusListTokenJwt,
                payload: to_json_object(sl_metadata)?,
            }),

            StatusListFormat::StatusListTokenCwt => Ok(JsStatusListFormat {
                format: JsStatusListFormatFmt::StatusListTokenCwt,
                payload: JsonObject::new(),
            }),
        }
    }
}

impl TryFrom<JsStatusListFormat> for StatusListFormat {
    type Error = Error;

    fn try_from(value: JsStatusListFormat) -> Result<Self, Error> {
        let result = match value.format {
            JsStatusListFormatFmt::StatusListTokenJwt => {
                StatusListFormat::StatusListTokenJwt(from_json_object(value.payload)?)
            }
            JsStatusListFormatFmt::StatusListTokenCwt => StatusListFormat::StatusListTokenCwt,
        };
        Ok(result)
    }
}

#[napi(string_enum)]
#[derive(Display)]
pub enum TslVcStatusType {
    VALID,
    INVALID,
    SUSPENDED,
    APPSPECIFIC,
}

impl From<AsdkTslVcStatus> for TslVcStatusType {
    fn from(value: AsdkTslVcStatus) -> Self {
        match value {
            VCStatus::Valid => Self::VALID,
            VCStatus::Invalid => Self::INVALID,
            VCStatus::Suspended => Self::SUSPENDED,
            VCStatus::AppSpecific(_) => Self::APPSPECIFIC,
        }
    }
}
