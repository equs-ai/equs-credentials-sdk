use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use oauth2::{HttpRequest, HttpResponse};
#[cfg(test)]
use oauth2::http::{Method, StatusCode};

pub use reqwest::ReqwestClient;

mod reqwest;

pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_JSON: &str = "application/json";

#[cfg_attr(test, automock)]
#[async_trait]
pub trait HttpClient: Sync + Send {
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse, reqwest::Error>;

    async fn static_async(request: HttpRequest) -> Result<HttpResponse, reqwest::Error>
    where
        Self: Sized;
}

#[cfg(test)]
pub fn mock_http<T: serde::Serialize + Send + Sync + 'static>(
    mock: &mut MockHttpClient,
    method: Method,
    url: url::Url,
    body: T,
    status: StatusCode,
) {
    mock
        .expect_async_call()
        .withf(move |req| {
            let method = req.method == method;
            let url = req.url == url;

            method && url
        })
        .times(1)
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
)
where
    F: FnMut(HttpRequest) -> Result<HttpResponse, reqwest::Error> + Send + 'static,
{
    mock
        .expect_async_call()
        .withf(move |req| {
            let method = req.method == method;
            let url = req.url == url;

            method && url
        })
        .times(times)
        .returning(body_fn);
}

#[cfg(test)]
pub fn mock_static_ctx<T: serde::Serialize + Send + Sync + 'static>(
    ctx: &__mock_MockHttpClient_HttpClient::__static_async::Context,
    method: Method,
    url: url::Url,
    body: T,
    status: StatusCode,
) {
    ctx
        .expect()
        .withf(move |req| {
            let method = req.method == method;
            let url = req.url == url;

            method && url
        })
        .times(1)
        .returning(move |_| Ok(HttpResponse {
            status_code: StatusCode::OK,
            headers: Default::default(),
            body: serde_json::to_vec(&body).unwrap(),
        }));
}
