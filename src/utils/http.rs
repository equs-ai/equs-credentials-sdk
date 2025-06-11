use crate::http::HttpSnafu;
use oauth2::HttpRequest;
use oauth2::http::header::CONTENT_TYPE;
use oauth2::http::{HeaderMap, Method};
use reqwest::header::{ACCEPT, HeaderValue};
use serde::{Deserialize, Serialize};
use strum_macros::Display;
use url::Url;

pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_OAUTH_REQ_JWT: &str = "application/oauth-authz-req+jwt";
pub const MIME_TYPE_TEXT_PLAIN: &str = "text/plain";
pub const MIME_STATUSLIST_JWT: &str = "application/statuslist+jwt";
pub const MIME_STATUSLIST_CWT: &str = "application/statuslist+cwt";
pub const MIME_DIDCOMM_ENCRYPTED_JSON: &str = "application/didcomm-encrypted+json";

#[derive(Display, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum MimeType {
    AppFormUrlEnc,
    AppJson,
    TextPlain,
}

impl MimeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MimeType::AppFormUrlEnc => MIME_TYPE_FORM_URLENCODED,
            MimeType::AppJson => MIME_TYPE_JSON,
            MimeType::TextPlain => MIME_TYPE_TEXT_PLAIN,
        }
    }
}

pub(crate) fn generate_post_req(
    url: &Url,
    content_type: MimeType,
    accept: MimeType,
    body: Vec<u8>,
) -> crate::http::Result<HttpRequest> {
    let mut request = HttpRequest::new(body);
    *request.headers_mut() = HeaderMap::from_iter(vec![
        (
            CONTENT_TYPE,
            HeaderValue::from_static(content_type.as_str()),
        ),
        (ACCEPT, HeaderValue::from_static(accept.as_str())),
    ]);
    *request.method_mut() = Method::POST;
    *request.uri_mut() = oauth2::http::Uri::try_from(url.to_string()).map_err(|e| {
        HttpSnafu {
            details: format!("could not build post request uri: {e}"),
        }
        .build()
    })?;

    Ok(request)
}

#[cfg(test)]
pub mod test {
    use crate::http::{MockHttpClient, Result};
    use futures::executor;
    use oauth2::http::header::CONTENT_TYPE;
    use oauth2::http::{HeaderValue, Method, StatusCode};
    use oauth2::{HttpRequest, HttpResponse};
    use std::future::Future;
    use url::Url;

    #[cfg(test)]
    pub fn mock_http_once<T: serde::Serialize + Send + Sync + 'static>(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        body: T,
        status: StatusCode,
    ) {
        mock_http(mock, method, url, body, status, 1.into());
    }

    #[cfg(test)]
    pub fn mock_http<T: serde::Serialize + Send + Sync + 'static>(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        body: T,
        status: StatusCode,
        times: mockall::TimesRange,
    ) {
        mock.expect_async_call()
            .withf(move |req| {
                let method = req.method() == method;
                let url = req.uri().to_string() == url.to_string();

                method && url
            })
            .times(times)
            .returning(move |_| {
                let mut resp = HttpResponse::new(serde_json::to_vec(&body).unwrap());
                *resp.status_mut() = status;

                Ok(resp)
            });
    }

    #[cfg(test)]
    pub fn mock_http_req_body<T: serde::Serialize + Send + Sync + 'static>(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        expected_req_body: String,
        body: T,
        status: StatusCode,
        times: mockall::TimesRange,
    ) {
        mock.expect_async_call()
            .withf(move |req| {
                let method = req.method() == method;
                let url = req.uri().to_string() == url.to_string();
                let body = String::from_utf8(req.body().clone()).expect("Found invalid UTF-8")
                    == expected_req_body;

                method && url && body
            })
            .times(times)
            .returning(move |_| {
                let mut resp = HttpResponse::new(serde_json::to_vec(&body).unwrap());
                *resp.status_mut() = status;

                Ok(resp)
            });
    }

    #[cfg(test)]
    pub fn mock_http_req_predicate<T, F>(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        expected_req_body_predicate: F,
        body: T,
        status: StatusCode,
        times: mockall::TimesRange,
    ) where
        T: serde::Serialize + Send + Sync + 'static,
        F: Fn(String) -> bool + Send + 'static,
    {
        mock.expect_async_call()
            .withf(move |req| {
                let method = req.method() == method;
                let url = req.uri().to_string() == url.to_string();

                method
                    && url
                    && expected_req_body_predicate(String::from_utf8(req.body().clone()).unwrap())
            })
            .times(times)
            .returning(move |_| {
                let mut resp = HttpResponse::new(serde_json::to_vec(&body).unwrap());
                *resp.status_mut() = status;

                Ok(resp)
            });
    }

    pub fn mock_http_req_async_predicate<T, FN, F>(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        expected_req_body_predicate: FN,
        body: T,
        status: StatusCode,
        times: mockall::TimesRange,
    ) where
        T: serde::Serialize + Send + Sync + 'static,
        FN: Fn(String) -> F + Send + 'static,
        F: Future<Output = bool>,
    {
        mock_http_req_predicate(
            mock,
            method,
            url,
            move |req_body| executor::block_on(expected_req_body_predicate(req_body)),
            body,
            status,
            times,
        );
    }

    pub fn mock_http_fn_with_plain_text_resp(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        body: &'static str,
        times: mockall::TimesRange,
    ) {
        mock_http_fn(
            mock,
            method,
            url,
            move |req| {
                let mut resp = HttpResponse::new(Vec::from(body));
                resp.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_str("text/plain").unwrap());

                Ok(resp)
            },
            1.into(),
        );
    }

    #[cfg(test)]
    pub fn mock_http_fn<F>(
        mock: &mut MockHttpClient,
        method: Method,
        url: Url,
        body_fn: F,
        times: mockall::TimesRange,
    ) where
        F: FnMut(HttpRequest) -> Result<HttpResponse> + Send + 'static,
    {
        mock.expect_async_call()
            .withf(move |req| {
                let method = req.method() == method;
                let url = req.uri().to_string() == url.to_string();

                method && url
            })
            .times(times)
            .returning(body_fn);
    }
}
