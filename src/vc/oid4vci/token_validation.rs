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
use oid4vci::openidconnect::{JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl};
use reqwest::StatusCode;
use snafu::{ensure, Location, ResultExt, Snafu};
use std::fmt::Debug;
use tracing::{debug, instrument, trace, Level};
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
        source: ssi::jws::Error,
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
    #[instrument(
        level = Level::TRACE,
        skip(http_client),
    )]
    pub fn new(http_client: HC, introspect_endpoint: Url, auth_header: Option<String>) -> Self {
        Self {
            http_client,
            introspect_endpoint,
            auth_header,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
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

        let token_int_resp =
            serde_json::from_slice::<IntrospectionResponse>(response.body.as_slice())
                .context(ParseSnafu)?;

        trace!(token_introspection_response = ?token_int_resp);

        ensure!(
            token_int_resp.active(),
            TokenSnafu {
                details: "Token is expired"
            }
        );

        debug!("access token is valid");

        Ok(())
    }
}

pub struct ByJwks<HC: HttpClient> {
    http_client: HC,
    jwks_url: JsonWebKeySetUrl,
}

impl<HC: HttpClient> ByJwks<HC> {
    #[instrument(
        level = Level::TRACE,
        skip(http_client)
    )]
    pub fn new(http_client: HC, jwks_url: JsonWebKeySetUrl) -> Self {
        Self {
            http_client,
            jwks_url,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    pub async fn validate(&self, token: &str) -> Result<()> {
        let jwks = JsonWebKeySet::<
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
            CoreJsonWebKeyUse,
            CoreJsonWebKey,
        >::fetch_async(&self.jwks_url, |req| self.http_client.async_call(req))
        .await
        .context(DiscoverySnafu)?;

        let (header, _) = ssi::jws::decode_unverified(token).map_err(|e| {
            TokenSnafu {
                details: format!("Can not parse the header of the token: {e}"),
            }
            .build()
        })?;

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

        let jwk = serde_json::from_value(serde_json::to_value(key).context(ParseSnafu)?)
            .context(ParseSnafu)?;

        ssi::jws::decode_verify(token, &jwk).context(SignatureVerificationSnafu)?;

        debug!("access token is valid");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;
    use crate::utils::http::test::mock_http_fn;
    use crate::vc::oid4vci::tests::fixtures::{
        sample_introspect_response, sample_jwks, JWKS_URL, TOKEN_INTROSPECT_URL,
    };
    use oauth2::http::HeaderMap;
    use oauth2::HttpResponse;
    use serde_json::{json, Value};

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjY4NDY2NDcsImlhdCI6MTcyNjgxMDgzOSwiYXV0aF90aW1lIjoxNzI2ODEwNjQ3LCJqdGkiOiJlNWIxZjFjNC1kYjEzLTRkODgtYmJkMi0yN2NkMDkxYzc1ZGEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6IjFmZTg0ZWI3LTE5MTEtNDBlYi04ZGNmLWRiMzYwN2E2OGQ4ZiIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkX3Njb3BlIn0.Sj6R0q7nnumcspoZOMS6KhOFf4yCia9KAF4uSjUShLq4xUgO-GaprdFjk3zX6koNr1dj_fVdi0Kq0Msxm3JkgJ4tNJRksF_n2pGhgfTfsGW6llZr_ZcO_bYugWYbbyUuw88QqGVhVjdiGfffkg3YC6UP-2-nK96BgQGu9UmbSxSwYYeZdoCc1vqUglN_0zwZ3FSmZ9J12QBb7rvK-lPPMhKeXByaHyuz_MtQguEmi0GOg4J1v3DHQZz5aFEG7W9-zYKRVO3EXHgolOrzobnNgQyfpE0SzHkokLKrEddudbSATvUAT9DXihXHYCRPouf3pnSpV3WPl6Kxh46RdfNw-w";

    #[tokio::test]
    async fn introspect_validate_succeeds_by_correct_url() {
        let http_client = create_mock_http_client(
            TOKEN_INTROSPECT_URL,
            sample_introspect_response(),
            Method::POST,
            StatusCode::OK,
        );

        let validator =
            Introspect::new(http_client, Url::parse(TOKEN_INTROSPECT_URL).unwrap(), None);

        let result = validator.validate(TOKEN).await;

        result.unwrap()
    }

    #[tokio::test]
    async fn by_jwks_validate_succeeds_with_correct_token() {
        let http_client =
            create_mock_http_client(JWKS_URL, sample_jwks(), Method::GET, StatusCode::OK);

        let validator = ByJwks::new(
            http_client,
            JsonWebKeySetUrl::new(JWKS_URL.to_string()).unwrap(),
        );

        let result = validator.validate(TOKEN).await;

        result.unwrap()
    }

    #[tokio::test]
    #[should_panic(expected = "Token is invalid")]
    async fn introspect_validate_fails_on_non_ok_status() {
        let http_client = create_mock_http_client(
            TOKEN_INTROSPECT_URL,
            sample_introspect_response(),
            Method::POST,
            StatusCode::INTERNAL_SERVER_ERROR,
        );

        let validator =
            Introspect::new(http_client, Url::parse(TOKEN_INTROSPECT_URL).unwrap(), None);

        let result = validator.validate(TOKEN).await;

        result.unwrap()
    }

    #[tokio::test]
    #[should_panic(expected = "Token is expired")]
    async fn introspect_validate_fails_on_expired_token() {
        let http_client = create_mock_http_client(
            TOKEN_INTROSPECT_URL,
            json!({"active": false}),
            Method::POST,
            StatusCode::OK,
        );

        let validator =
            Introspect::new(http_client, Url::parse(TOKEN_INTROSPECT_URL).unwrap(), None);

        let result = validator.validate(TOKEN).await;

        result.unwrap()
    }

    fn create_mock_http_client(
        url: &str,
        body: Value,
        method: Method,
        status: StatusCode,
    ) -> MockHttpClient {
        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            method,
            Url::parse(url).unwrap(),
            move |req| {
                let resp = HttpResponse {
                    status_code: status,
                    headers: HeaderMap::from_iter(vec![(
                        CONTENT_TYPE,
                        HeaderValue::from_str(MIME_TYPE_JSON).unwrap(),
                    )]),
                    body: serde_json::to_vec(&body).unwrap(),
                };

                Ok(resp)
            },
            1.into(),
        );
        http_client
    }
}
