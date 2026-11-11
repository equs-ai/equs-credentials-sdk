use crate::http::HttpSnafu;
use crate::reqwest::validators::content_size::ContentSizeLimiter;
use crate::reqwest::validators::content_type::ContentTypeValidator;
use oauth2::{HttpRequest, HttpResponse};
use tracing::warn;

#[derive(Debug, Clone)]
pub struct WasmClient {
    pub client: reqwest::Client,
    pub content_size_limiter: ContentSizeLimiter,
    pub content_type_validator: ContentTypeValidator,
    pub insecure: bool,
}

impl WasmClient {
    pub async fn async_call(&self, request: HttpRequest) -> crate::http::Result<HttpResponse> {
        let (parts, body) = request.into_parts();

        if !self.insecure && parts.uri.scheme_str() != Some("https") {
            return Err(HttpSnafu {
                details: "Only HTTPS connections are allowed".to_string(),
            }
            .build());
        }

        let content_type_to_accept = self
            .content_type_validator
            .resolve_request_content_type(&parts.headers)
            .map_err(|err| {
                HttpSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        let body_size = body.len();
        if self
            .content_size_limiter
            .is_req_body_out_of_limit(body_size)
        {
            warn!(
                "Request body size is out of limit: request body size = {}",
                body_size
            );
        }

        let mut request_builder = self
            .client
            .request(parts.method, parts.uri.to_string())
            .body(body);

        for (name, value) in parts.headers.iter() {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }

        let req = request_builder.build().map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let response = self.client.execute(req).await.map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        self.content_size_limiter
            .validate_content_length_header(&response)?;

        let status_code = response.status();
        let headers = response.headers().to_owned();

        let resp_body = self
            .content_size_limiter
            .read_response_body(response)
            .await?;

        self.content_type_validator
            .validate_response_content_type(&content_type_to_accept, &headers, &resp_body)
            .await?;

        let mut response = HttpResponse::new(resp_body);
        *response.status_mut() = status_code;
        *response.headers_mut() = headers;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::http::MIME_TYPE_JSON;
    use oauth2::http::header::ACCEPT;
    use oauth2::http::{self, Method};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};

    const CHUNKED_JSON_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
        Transfer-Encoding: chunked\r\n\r\n\
        8\r\n{\"a\":\"bc\r\n8\r\ndefghi\"}\r\n0\r\n\r\n";

    #[tokio::test]
    async fn async_call_rejects_a_body_over_the_limit_without_content_length() {
        let addr = serve_once(CHUNKED_JSON_RESPONSE);
        let client = client(ContentSizeLimiter::unlimited().with_response_size_limit(10));

        let err = client.async_call(request(addr)).await.unwrap_err();

        assert!(err.to_string().contains("exceeds the limit"), "{err}");
    }

    #[tokio::test]
    async fn async_call_reads_a_chunked_body_within_the_limit() {
        let addr = serve_once(CHUNKED_JSON_RESPONSE);
        let client = client(ContentSizeLimiter::unlimited().with_response_size_limit(16));

        let response = client.async_call(request(addr)).await.unwrap();

        assert_eq!(response.body().as_slice(), br#"{"a":"bcdefghi"}"#);
    }

    fn serve_once(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response);
        });
        addr
    }

    fn client(content_size_limiter: ContentSizeLimiter) -> WasmClient {
        WasmClient {
            client: reqwest::Client::new(),
            content_size_limiter,
            content_type_validator: ContentTypeValidator,
            insecure: true,
        }
    }

    fn request(addr: SocketAddr) -> HttpRequest {
        http::request::Builder::new()
            .uri(format!("http://{addr}/"))
            .method(Method::GET)
            .header(ACCEPT, MIME_TYPE_JSON)
            .body(vec![])
            .unwrap()
    }
}
