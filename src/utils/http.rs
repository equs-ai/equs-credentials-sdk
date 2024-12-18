use oauth2::http::header::CONTENT_TYPE;
use oauth2::http::{HeaderMap, Method};
use oauth2::HttpRequest;
use reqwest::header::{HeaderValue, ACCEPT};
use url::Url;

pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_TEXT_PLAIN: &str = "text/plain";

pub(crate) enum MimeType {
    AppFormUrlEnc,
    AppJson,
    TextPlain,
}

impl MimeType {
    fn as_str(&self) -> &'static str {
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
) -> HttpRequest {
    HttpRequest {
        url: url.to_owned(),
        method: Method::POST,
        headers: HeaderMap::from_iter(vec![
            (
                CONTENT_TYPE,
                HeaderValue::from_static(content_type.as_str()),
            ),
            (ACCEPT, HeaderValue::from_static(accept.as_str())),
        ]),
        body,
    }
}
#[cfg(test)]
pub mod test {
    use crate::http::{MockHttpClient, Result};
    use futures::executor;
    use oauth2::http::header::CONTENT_TYPE;
    use oauth2::http::{HeaderMap, HeaderValue, Method, StatusCode};
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
                let method = req.method == method;
                let url = req.url == url;

                method && url
            })
            .times(times)
            .returning(move |_| {
                Ok(HttpResponse {
                    status_code: status,
                    headers: Default::default(),
                    body: serde_json::to_vec(&body).unwrap(),
                })
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
                let method = req.method == method;
                let url = req.url == url;
                let body = String::from_utf8(req.body.clone()).expect("Found invalid UTF-8")
                    == expected_req_body;

                method && url && body
            })
            .times(times)
            .returning(move |_| {
                Ok(HttpResponse {
                    status_code: status,
                    headers: Default::default(),
                    body: serde_json::to_vec(&body).unwrap(),
                })
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
                let method = req.method == method;
                let url = req.url == url;

                method
                    && url
                    && expected_req_body_predicate(String::from_utf8(req.body.clone()).unwrap())
            })
            .times(times)
            .returning(move |_| {
                Ok(HttpResponse {
                    status_code: status,
                    headers: Default::default(),
                    body: serde_json::to_vec(&body).unwrap(),
                })
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
                let resp = HttpResponse {
                    status_code: StatusCode::OK,
                    headers: HeaderMap::from_iter(vec![(
                        CONTENT_TYPE,
                        HeaderValue::from_str("text/plain").unwrap(),
                    )]),
                    body: Vec::from(body),
                };

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
                let method = req.method == method;
                let url = req.url == url;

                method && url
            })
            .times(times)
            .returning(body_fn);
    }
}
