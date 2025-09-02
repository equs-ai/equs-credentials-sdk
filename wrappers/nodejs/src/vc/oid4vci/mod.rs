pub mod builder;
pub mod credential_offer_resolver;
pub mod error;
pub mod holder;
pub mod issuer;

use crate::vc::oid4vci::builder::TokenValidation;
use napi::Error;
use napi_derive::napi;
use time::Duration;

#[napi(js_name = "TokenValidationEnum")]
pub enum JsTokenValidationEnum {
    Introspect,
    Jwks,
}

#[napi(js_name = "TokenValidation", object)]
pub struct JsTokenValidation {
    pub type_: JsTokenValidationEnum,
    pub url: String,
    pub header: Option<String>,
}

impl TryFrom<TokenValidation> for JsTokenValidation {
    type Error = Error;

    fn try_from(value: TokenValidation) -> Result<Self, Error> {
        match value {
            TokenValidation::Introspect(url, header) => Ok(JsTokenValidation {
                type_: JsTokenValidationEnum::Introspect,
                url,
                header,
            }),

            TokenValidation::Jwks(url) => Ok(JsTokenValidation {
                type_: JsTokenValidationEnum::Jwks,
                url,
                header: None,
            }),
        }
    }
}

impl TryFrom<JsTokenValidation> for TokenValidation {
    type Error = Error;

    fn try_from(value: JsTokenValidation) -> Result<Self, Error> {
        let result = match value.type_ {
            JsTokenValidationEnum::Introspect => {
                TokenValidation::Introspect(value.url, value.header)
            }
            JsTokenValidationEnum::Jwks => TokenValidation::Jwks(value.url),
        };
        Ok(result)
    }
}

#[napi(js_name = "Duration", object)]
pub struct JsDuration {
    pub seconds: i64,
    pub nanoseconds: i32,
}

impl From<Duration> for JsDuration {
    fn from(duration: Duration) -> Self {
        JsDuration {
            seconds: duration.whole_seconds(),
            nanoseconds: duration.subsec_nanoseconds(),
        }
    }
}

impl TryFrom<JsDuration> for Duration {
    type Error = Error;

    fn try_from(js_duration: JsDuration) -> Result<Self, Error> {
        Ok(Duration::new(js_duration.seconds, js_duration.nanoseconds))
    }
}
