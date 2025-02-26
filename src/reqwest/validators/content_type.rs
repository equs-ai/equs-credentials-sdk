use super::{ContentTypeSnafu, Result};
use crate::utils::http::{
    MIME_STATUSLIST_CWT, MIME_STATUSLIST_JWT, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON,
    MIME_TYPE_OAUTH_REQ_JWT, MIME_TYPE_TEXT_PLAIN,
};
use mime::Mime;
use oauth2::http::header::ACCEPT;
use oauth2::http::{HeaderMap, HeaderValue};
use reqwest::header::CONTENT_TYPE;
use snafu::ensure;
use std::str::FromStr;
use tracing::{instrument, Level};

const ALLOWED_CONTENT_TYPE_HEADERS: [&str; 6] = [
    MIME_TYPE_JSON,
    MIME_TYPE_TEXT_PLAIN,
    MIME_TYPE_FORM_URLENCODED,
    MIME_TYPE_OAUTH_REQ_JWT,
    MIME_STATUSLIST_JWT,
    MIME_STATUSLIST_CWT,
];

#[derive(Clone, Debug)]
pub struct ContentTypeValidator;

impl ContentTypeValidator {
    #[instrument(level = Level::TRACE, skip(self), ret(), err())]
    pub async fn validate_response_content_type(
        &self,
        content_type_to_accept: &HeaderValue,
        headers: &HeaderMap,
        response_body: &[u8],
    ) -> Result<()> {
        if response_body.is_empty() {
            return Ok(());
        }

        let content_type = headers.get(CONTENT_TYPE).ok_or_else(|| {
            ContentTypeSnafu {
                details: format!(
                    "Content-type is missed in response: accepted {:?}",
                    content_type_to_accept
                ),
            }
            .build()
        })?;

        let Some(content_type_as_str) = Self::resolve_supported_content_type(content_type) else {
            ContentTypeSnafu {
                details: format!(
                    "HTTP response content-type = '{}' to accept is not allowed",
                    content_type.to_str().unwrap_or("")
                ),
            }
            .fail()?
        };

        Self::compare_content_types(content_type_to_accept, content_type)?;

        if content_type_as_str.contains(MIME_TYPE_JSON) {
            let _ = serde_json::from_slice::<serde_json::Value>(response_body).map_err(|_| {
                ContentTypeSnafu {
                    details: "Response body is not a json".to_string(),
                }
                .build()
            })?;
        }

        if content_type_as_str.contains(MIME_TYPE_FORM_URLENCODED) {
            let _ = serde_urlencoded::from_bytes::<Vec<(String, String)>>(response_body).map_err(
                |_| {
                    ContentTypeSnafu {
                        details: "Response body is not a form url encoded".to_string(),
                    }
                    .build()
                },
            )?;
        }

        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    pub fn resolve_request_content_type(&self, headers: &HeaderMap) -> Result<HeaderValue> {
        let content_type = headers.get(ACCEPT).ok_or_else(|| ContentTypeSnafu {
            details: format!(
                "HTTP request content-type to accept is not declared: acceptable content types: '{}'",
                ALLOWED_CONTENT_TYPE_HEADERS.join(", ")
            ),
        }.build())?;

        if Self::resolve_supported_content_type(content_type).is_none() {
            ContentTypeSnafu {
                details: format!(
                    "HTTP request content-type = '{}' to accept is not allowed. Acceptable content types: '{}'",
                    content_type.to_str().unwrap_or(""),
                    ALLOWED_CONTENT_TYPE_HEADERS.join(", ")
                ),
            }
                .fail()?
        }

        Ok(content_type.to_owned())
    }

    #[instrument(level = Level::TRACE, ret(), err())]
    fn compare_content_types(
        content_type_to_accept: &HeaderValue,
        content_type: &HeaderValue,
    ) -> Result<()> {
        let content_type = Self::header_value_to_mime(content_type);
        let content_type_to_accept = Self::header_value_to_mime(content_type_to_accept);

        if let (Some(content_type), Some(content_type_to_accept)) =
            (content_type, content_type_to_accept)
        {
            ensure!(
                content_type_to_accept.essence_str() == content_type.essence_str(),
                ContentTypeSnafu {
                    details: format!(
                        "Content-type is mismatched: accepted {:?} , received {:?}",
                        content_type_to_accept, content_type
                    ),
                }
            );

            for (name, value) in content_type_to_accept.params() {
                let value_to_check = content_type.get_param(name);

                ensure!(
                    value_to_check == Some(value),
                    ContentTypeSnafu {
                        details: format!(
                            "Content-type is mismatched: accepted {:?} , received {:?}",
                            content_type_to_accept, content_type
                        ),
                    }
                );
            }
        }

        Ok(())
    }

    fn resolve_supported_content_type(header_val: &HeaderValue) -> Option<&str> {
        header_val.to_str().ok().and_then(|c_to_check| {
            ALLOWED_CONTENT_TYPE_HEADERS
                .into_iter()
                .find(|c| c_to_check.starts_with(c))
        })
    }

    fn header_value_to_mime(header_val: &HeaderValue) -> Option<Mime> {
        header_val
            .to_str()
            .ok()
            .and_then(|c| Mime::from_str(c).ok())
    }
}
