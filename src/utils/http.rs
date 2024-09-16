pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_JSON: &str = "application/json";

#[cfg(test)]
pub mod test {
    use crate::http::{MockHttpClient, Result};
    use oauth2::http::{Method, StatusCode};
    use oauth2::{HttpRequest, HttpResponse};

    #[cfg(test)]
    pub fn mock_http_once<T: serde::Serialize + Send + Sync + 'static>(
        mock: &mut MockHttpClient,
        method: Method,
        url: url::Url,
        body: T,
        status: StatusCode,
    ) {
        mock_http(mock, method, url, body, status, 1.into());
    }

    #[cfg(test)]
    pub fn mock_http<T: serde::Serialize + Send + Sync + 'static>(
        mock: &mut MockHttpClient,
        method: Method,
        url: url::Url,
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
        url: url::Url,
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
        url: url::Url,
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

    #[cfg(test)]
    pub fn mock_http_fn<F>(
        mock: &mut MockHttpClient,
        method: Method,
        url: url::Url,
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
