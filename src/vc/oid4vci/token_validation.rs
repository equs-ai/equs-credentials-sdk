use crate::http::{HttpClient, HttpError};
use crate::utils::http::{MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON};
use crate::utils::logs::sanitize_log_msg;
use common_macros::DebugError;
use oauth2::basic::BasicTokenType;
use oauth2::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, InvalidHeaderValue};
use oauth2::http::uri::InvalidUri;
use oauth2::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use oauth2::{
    EmptyExtraTokenFields, StandardTokenIntrospectionResponse, TokenIntrospectionResponse,
};
use openidconnect::core::CoreJsonWebKey;
use openidconnect::{DiscoveryError, JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl};
use snafu::{Location, ResultExt, Snafu, ensure};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{Level, debug, instrument, trace};
use url::Url;

pub type Result<T> = core::result::Result<T, Error>;

type IntrospectionResponse =
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>;

#[derive(Snafu, DebugError)]
pub enum Error {
    // Expected
    #[snafu(display("Token validation error: {details}"))]
    Token {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    // Unexpected
    #[snafu(display("Network error"))]
    Network {
        #[snafu(implicit)]
        location: Location,
        source: HttpError,
    },
    #[snafu(display("URL parse error"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Invalid uri error"))]
    InvalidUri {
        #[snafu(implicit)]
        location: Location,
        source: InvalidUri,
    },
    #[snafu(display("Parse error"))]
    Parse {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Invalid header error"))]
    InvalidHeader {
        #[snafu(implicit)]
        location: Location,
        source: InvalidHeaderValue,
    },
    #[snafu(display("Discovery error"))]
    Discovery {
        #[snafu(implicit)]
        location: Location,
        source: DiscoveryError<HttpError>,
    },
    #[snafu(display("Signature verification error"))]
    SignatureVerification {
        #[snafu(implicit)]
        location: Location,
        source: ssi::claims::jws::Error,
    },
    #[snafu(display("Request builder error"))]
    RequestBuilder {
        #[snafu(implicit)]
        location: Location,
        source: oauth2::http::Error,
    },
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

        let mut builder = Request::head(
            Uri::from_str(self.introspect_endpoint.as_ref()).context(InvalidUriSnafu)?,
        )
        .method(Method::POST);

        let default_headers = &mut HeaderMap::new();
        let builder_headers = builder.headers_mut().unwrap_or(default_headers);
        for (key, value) in headers {
            builder_headers.append(key, value);
        }

        let request = builder.body(body).context(RequestBuilderSnafu)?;

        let response = self
            .http_client
            .async_call(request)
            .await
            .context(NetworkSnafu)?;

        ensure!(
            response.status() == StatusCode::OK,
            TokenSnafu {
                details: "Token is invalid"
            }
        );

        let token_int_resp =
            serde_json::from_slice::<IntrospectionResponse>(response.body().as_slice())
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

/// Requires a numeric `exp` in the future and, when present, a numeric `nbf` in the past, both
/// within `clock_skew_secs`.
fn check_validity_window(payload: &[u8], clock_skew_secs: i64) -> Result<()> {
    let claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(payload).context(ParseSnafu)?;
    let numeric_date = |name: &str| -> Result<Option<i64>> {
        claims
            .get(name)
            .map(|v| {
                v.as_f64().map(|t| t as i64).ok_or_else(|| {
                    TokenSnafu {
                        details: format!("\"{name}\" is not a numeric date"),
                    }
                    .build()
                })
            })
            .transpose()
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    let exp = numeric_date("exp")?.ok_or_else(|| {
        TokenSnafu {
            details: "\"exp\" not found in the token",
        }
        .build()
    })?;
    ensure!(
        now < exp.saturating_add(clock_skew_secs),
        TokenSnafu {
            details: "Token is expired"
        }
    );
    if let Some(nbf) = numeric_date("nbf")? {
        ensure!(
            nbf.saturating_sub(clock_skew_secs) <= now,
            TokenSnafu {
                details: "Token is not yet valid"
            }
        );
    }
    Ok(())
}

pub struct ByJwks<HC: HttpClient> {
    http_client: Arc<HC>,
    jwks_url: JsonWebKeySetUrl,
    clock_skew: time::Duration,
}

impl<HC: HttpClient> ByJwks<HC> {
    #[instrument(
        level = Level::TRACE,
        skip(http_client)
    )]
    /// `clock_skew` is how far `exp` and `nbf` may be off between the authorization server and
    /// the issuer; without it, both are checked exactly.
    pub fn new(
        http_client: HC,
        jwks_url: JsonWebKeySetUrl,
        clock_skew: Option<time::Duration>,
    ) -> Self {
        Self {
            http_client: Arc::new(http_client),
            jwks_url,
            clock_skew: clock_skew.unwrap_or_default(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    pub async fn validate(&self, token: &str) -> Result<()> {
        let http_callback = |req| {
            let client = self.http_client.clone();
            Box::pin(async move { client.async_call(req).await })
        };
        let jwks = JsonWebKeySet::<CoreJsonWebKey>::fetch_async(&self.jwks_url, &http_callback)
            .await
            .context(DiscoverySnafu)?;

        let (header, _) = ssi::claims::jws::decode_unverified(token).map_err(|e| {
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
                    details: format!(
                        "Token is signed with the unknown key: \"kid\" = {}",
                        sanitize_log_msg(&key_id)
                    ),
                }
                .build(),
            )?;

        let jwk = serde_json::from_value(serde_json::to_value(key).context(ParseSnafu)?)
            .context(ParseSnafu)?;

        let (_, payload) =
            ssi::claims::jws::decode_verify(token, &jwk).context(SignatureVerificationSnafu)?;
        check_validity_window(&payload, self.clock_skew.whole_seconds())?;

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
        JWKS_URL, TOKEN_INTROSPECT_URL, sample_introspect_response, sample_jwks,
    };
    use oauth2::HttpResponse;
    use serde_json::{Value, json};

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

        let result = validator.validate(&token()).await;

        result.unwrap()
    }

    #[tokio::test]
    async fn by_jwks_validate_succeeds_with_correct_token() {
        let http_client =
            create_mock_http_client(JWKS_URL, sample_jwks(), Method::GET, StatusCode::OK);

        let validator = ByJwks::new(
            http_client,
            JsonWebKeySetUrl::new(JWKS_URL.to_string()).unwrap(),
            None,
        );

        let result = validator.validate(&token()).await;

        result.unwrap()
    }

    #[rstest::rstest]
    #[case::expired(json!({ "exp": time::OffsetDateTime::now_utc().unix_timestamp() - 3600 }))]
    #[case::not_yet_valid(json!({ "nbf": time::OffsetDateTime::now_utc().unix_timestamp() + 3600 }))]
    #[case::missing_exp(json!({ "exp": null }))]
    #[case::non_numeric_exp(json!({ "exp": "99999999999" }))]
    #[case::non_numeric_nbf(json!({ "nbf": "0" }))]
    #[case::expired_a_moment_ago(json!({ "exp": time::OffsetDateTime::now_utc().unix_timestamp() - 30 }))]
    #[case::valid_in_a_moment(json!({ "nbf": time::OffsetDateTime::now_utc().unix_timestamp() + 30 }))]
    #[tokio::test]
    async fn by_jwks_validate_rejects_token_outside_its_validity_window(#[case] overrides: Value) {
        let http_client =
            create_mock_http_client(JWKS_URL, sample_jwks(), Method::GET, StatusCode::OK);
        let validator = ByJwks::new(
            http_client,
            JsonWebKeySetUrl::new(JWKS_URL.to_string()).unwrap(),
            None,
        );

        let result = validator.validate(&token_with(overrides)).await;

        assert!(
            result.is_err(),
            "token outside its validity window was accepted"
        );
    }

    #[rstest::rstest]
    #[case::expired_within_the_skew(json!({ "exp": time::OffsetDateTime::now_utc().unix_timestamp() - 30 }))]
    #[case::valid_within_the_skew(json!({ "nbf": time::OffsetDateTime::now_utc().unix_timestamp() + 30 }))]
    #[tokio::test]
    async fn by_jwks_validate_accepts_token_within_the_clock_skew(#[case] overrides: Value) {
        let http_client =
            create_mock_http_client(JWKS_URL, sample_jwks(), Method::GET, StatusCode::OK);
        let validator = ByJwks::new(
            http_client,
            JsonWebKeySetUrl::new(JWKS_URL.to_string()).unwrap(),
            Some(time::Duration::minutes(1)),
        );

        let result = validator.validate(&token_with(overrides)).await;

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

        let result = validator.validate(&token()).await;

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

        let result = validator.validate(&token()).await;

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
                let body = serde_json::to_vec(&body).unwrap();
                let mut resp = HttpResponse::new(body);
                resp.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON));
                *resp.status_mut() = status;

                Ok(resp)
            },
            1.into(),
        );
        http_client
    }

    fn token() -> String {
        token_with(json!({}))
    }

    /// An access token signed by the test authorization server, valid for the next hour,
    /// with `overrides` merged into (or, when `null`, removed from) its claims.
    fn token_with(overrides: Value) -> String {
        let authz = &test_fixtures::keys().authz;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut claims = json!({
            "exp": now + 3600,
            "iat": now,
            "auth_time": now,
            "jti": "e5b1f1c4-db13-4d88-bbd2-27cd091c75da",
            "iss": "http://localhost:8080/idp/realms/pid-issuer-realm",
            "sub": "60b8ba5f-c73f-4976-b0da-48d0e53335de",
            "typ": "Bearer",
            "azp": "wallet-dev",
            "sid": "1fe84eb7-1911-40eb-8dcf-db3607a68d8f",
            "allowed-origins": ["/*"],
            "scope": "SD_JWT_cred_scope"
        });
        let map = claims.as_object_mut().unwrap();
        for (k, v) in overrides.as_object().unwrap() {
            if v.is_null() {
                map.remove(k);
            } else {
                map.insert(k.clone(), v.clone());
            }
        }
        test_fixtures::jws(
            &json!({ "alg": "RS256", "typ": "JWT", "kid": authz.key_id }),
            &claims,
            authz,
        )
    }
}
