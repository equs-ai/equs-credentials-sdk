use oauth2::{HttpRequest, HttpResponse};
use reqwest::{Body, Client};

pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_JSON: &str = "application/json";

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    pub fn new(https_only: bool, invalid_certs: bool) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .https_only(https_only)
            .danger_accept_invalid_certs(invalid_certs)
            .build()?;

        Ok(Self { client })
    }

    pub async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse, reqwest::Error> {
        let mut request_builder = self.client
            .request(request.method, request.url.as_str())
            .body(request.body);

        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }

        let request = request_builder.build()?;

        println!("-----REQUEST SENT TO URL-----\n{}", request.url().to_string());
        println!("-----REQUEST BODY----- \n{}", Self::req_body_pretty(request.body()));

        let response = self.client.execute(request).await?;
        let status_code = response.status();
        let headers = response.headers().to_owned();
        let chunks = response.bytes().await?;

        println!("-----RESPONSE STATUS----- \n{}", status_code);
        println!("-----RESPONSE BODY----- \n{}", Self::vec_pretty(chunks.to_vec()));

        Ok(HttpResponse {
            status_code,
            headers,
            body: chunks.to_vec(),
        })
    }

    fn req_body_pretty(body: Option<&Body>) -> String {
        if body.is_none() { return "No body".to_string(); }

        let bytes = body.unwrap().as_bytes();
        let Some(vec) = bytes.map(|b| b.to_vec()) else { return "Empty body".to_string(); };

        Self::vec_pretty(vec)
    }

    fn vec_pretty(vec: Vec<u8>) -> String {
        if vec.is_empty() { return "Empty body".to_string(); }
        String::from_utf8(vec).unwrap_or("Failed to parse".to_string())
    }
}

pub async fn async_request(request: HttpRequest) -> Result<HttpResponse, reqwest::Error> {
    HttpClient::new(false, true)?.async_call(request).await
}