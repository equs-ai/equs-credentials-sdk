use crate::http::{HttpClient, HttpError};
use crate::utils::http::{MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON};
use oauth2::basic::BasicTokenType;
use oauth2::http::header::{InvalidHeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use oauth2::http::{HeaderValue, Method};
use oauth2::{
    EmptyExtraTokenFields, HttpRequest, StandardTokenIntrospectionResponse,
    TokenIntrospectionResponse,
};
use oid4vci::openidconnect;
use oid4vci::openidconnect::core::{
    CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJwsSigningAlgorithm,
};
use oid4vci::openidconnect::{
    JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl, SignatureVerificationError,
};
use reqwest::StatusCode;
use snafu::{ensure, Location, ResultExt, Snafu};
use std::fmt::Debug;
use url::Url;

pub type Result<T> = core::result::Result<T, Error>;

type IntrospectionResponse =
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>;

#[derive(Snafu)]
pub enum Error {
    // Expected
    #[snafu(display("Token validation error at {location}\n Cause: {details}"))]
    Token {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    // Unexpected
    #[snafu(display("Network error at {location}"))]
    Network {
        #[snafu(implicit)]
        location: Location,
        source: HttpError,
    },
    #[snafu(display("URL parse error at {location}"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Parse error at {location}"))]
    Parse {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Invalid header error at {location}"))]
    InvalidHeader {
        #[snafu(implicit)]
        location: Location,
        source: InvalidHeaderValue,
    },
    #[snafu(display("Discovery error at {location}"))]
    Discovery {
        #[snafu(implicit)]
        location: Location,
        source: openidconnect::DiscoveryError<HttpError>,
    },
    #[snafu(display("Signature verification error at {location}"))]
    SignatureVerification {
        #[snafu(implicit)]
        location: Location,
        source: SignatureVerificationError,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
}

pub struct Introspect<HC: HttpClient> {
    http_client: HC,
    introspect_endpoint: Url,
    auth_header: Option<String>,
}

impl<HC: HttpClient> Introspect<HC> {
    pub fn new(http_client: HC, introspect_endpoint: Url, auth_header: Option<String>) -> Self {
        Self {
            http_client,
            introspect_endpoint,
            auth_header,
        }
    }

    pub async fn validate(&self, token: &str) -> Result<()> {
        let body = Vec::from(format!("token={}", token));

        let mut headers = vec![
            (
                CONTENT_TYPE,
                HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED),
            ),
            (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
        ];

        if let Some(header) = &self.auth_header {
            let header = HeaderValue::from_str(header).context(InvalidHeaderSnafu)?;
            headers.push((AUTHORIZATION, header));
        }

        let request = HttpRequest {
            url: self.introspect_endpoint.clone(),
            method: Method::POST,
            headers: headers.into_iter().collect(),
            body,
        };

        let response = self
            .http_client
            .async_call(request)
            .await
            .context(NetworkSnafu)?;

        ensure!(
            response.status_code == StatusCode::OK,
            TokenSnafu {
                details: "Token is invalid"
            }
        );

        let token_ifo = serde_json::from_slice::<IntrospectionResponse>(response.body.as_slice())
            .context(ParseSnafu)?;

        ensure!(
            token_ifo.active(),
            TokenSnafu {
                details: "Token is expired"
            }
        );

        Ok(())
    }
}

pub struct ByJwks<HC: HttpClient> {
    http_client: HC,
    jwks_url: JsonWebKeySetUrl,
}

impl<HC: HttpClient> ByJwks<HC> {
    pub fn new(http_client: HC, jwks_url: JsonWebKeySetUrl) -> Self {
        Self {
            http_client,
            jwks_url,
        }
    }

    pub async fn validate(&self, token: &str) -> Result<()> {
        let jwks = JsonWebKeySet::<
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
            CoreJsonWebKeyUse,
            CoreJsonWebKey,
        >::fetch_async(&self.jwks_url, |req| self.http_client.async_call(req))
        .await
        .context(DiscoverySnafu)?;

        let (header, signature) = if let Ok(header) = ssi::jws::decode_unverified(token) {
            header
        } else {
            return TokenSnafu {
                details: "Can not parse the token",
            }
            .fail();
        };

        let key_id = header.key_id.ok_or(
            TokenSnafu {
                details: "\"kid\" not found in the header of the token",
            }
            .build(),
        )?;

        let key = jwks
            .keys()
            .iter()
            .find(|k| k.key_id() == Some(&JsonWebKeyId::new(key_id.to_owned())))
            .ok_or(
                TokenSnafu {
                    details: format!("Token is signed with the unknown key: \"kid\" = {}", key_id),
                }
                .build(),
            )?;

        let alg: CoreJwsSigningAlgorithm = serde_json::from_str(
            serde_json::to_string(&header.algorithm)
                .context(ParseSnafu)?
                .as_str(),
        )
        .context(ParseSnafu)?;

        key.verify_signature(&alg, token.as_bytes(), signature.as_slice())
            .context(SignatureVerificationSnafu)?;

        Ok(())
    }
}
