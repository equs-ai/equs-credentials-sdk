pub mod builder;
pub mod credential_offer_resolver;
pub mod error;
pub mod holder;
pub mod issuer;
pub mod metadata;

use crate::vc::oid4vci::builder::TokenValidation;
use equs_sdk::vc::oid4vci::{CredentialLifetime, Notification, NotificationEvent};
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

#[napi(js_name = "CredentialLifetime")]
pub struct JsCredentialLifetime(CredentialLifetime);

#[napi]
impl JsCredentialLifetime {
    #[napi(factory)]
    pub fn infinite() -> Self {
        Self(CredentialLifetime::Infinite)
    }

    #[napi(factory)]
    pub fn finite(lifetime: i64) -> Result<Self, napi::Error> {
        if lifetime > 0 {
            Ok(Self(CredentialLifetime::Finite(Duration::seconds(
                lifetime,
            ))))
        } else {
            Err(napi::Error::from_reason(
                "Credential lifetime must be a positive number",
            ))
        }
    }
}

impl From<JsCredentialLifetime> for CredentialLifetime {
    fn from(value: JsCredentialLifetime) -> Self {
        value.0
    }
}

#[napi(js_name = "CredentialNotification", object)]
pub struct JsNotification {
    #[napi(js_name = "notification_id")]
    pub notification_id: String,
    pub event: JsNotificationEvent,
    #[napi(js_name = "event_description")]
    pub event_description: Option<String>,
}

#[napi(string_enum = "snake_case", js_name = "CredentialNotificationEvent")]
pub enum JsNotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

impl From<JsNotification> for Notification {
    fn from(value: JsNotification) -> Self {
        Self::new(
            value.notification_id,
            value.event.into(),
            value.event_description,
        )
    }
}

impl From<JsNotificationEvent> for NotificationEvent {
    fn from(value: JsNotificationEvent) -> Self {
        match value {
            JsNotificationEvent::CredentialAccepted => Self::CredentialAccepted,
            JsNotificationEvent::CredentialFailure => Self::CredentialFailure,
            JsNotificationEvent::CredentialDeleted => Self::CredentialDeleted,
        }
    }
}
