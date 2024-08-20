use oauth2::{EmptyExtraTokenFields, HttpRequest, StandardTokenIntrospectionResponse, TokenIntrospectionResponse};
use oauth2::basic::BasicTokenType;
use oauth2::http::{HeaderValue, Method};
use oauth2::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, InvalidHeaderValue};
use reqwest::StatusCode;
use url::Url;

use crate::utils::http::{HttpClient, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON};

pub type Result<T> = core::result::Result<T, Error>;

type IntrospectionResponse = StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error
{
    // Expected
    #[error("Token is expired")]
    ExpiredToken,
    #[error("Token is invalid")]
    InvalidToken,
    // Unexpected
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Url Parse Error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Parsing error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Parsing error: {0}")]
    InvalidHeader(#[from] InvalidHeaderValue),
}

pub struct Introspect<HC: HttpClient> {
    http_client: HC,
    introspect_endpoint: Url,
    auth_header: Option<String>,
}

impl<HC: HttpClient> Introspect<HC> {
    pub fn new(http_client: HC, introspect_endpoint: Url, auth_header: Option<String>) -> Self {
        Self { http_client, introspect_endpoint, auth_header }
    }

    pub async fn validate(&self, token: &str) -> Result<()> {
        let body = Vec::from(format!("token={}", token));

        let mut headers = vec![
            (CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED)),
            (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
        ];

        if let Some(header) = &self.auth_header {
            let header = HeaderValue::from_str(header)?;
            headers.push((AUTHORIZATION, header));
        }

        let request = HttpRequest {
            url: self.introspect_endpoint.clone(),
            method: Method::POST,
            headers: headers.into_iter().collect(),
            body,
        };

        let response = self.http_client.async_call(request).await?;
        if response.status_code != StatusCode::OK {
            return Err(Error::InvalidToken);
        }

        let token_ifo = serde_json::from_slice::<IntrospectionResponse>(response.body.as_slice())?;
        if !token_ifo.active() {
            return Err(Error::ExpiredToken);
        }

        Ok(())
    }
}