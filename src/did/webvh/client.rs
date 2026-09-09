//! did:webvh resolver.

use crate::did::universal::DIDResolver;
use crate::did::{ResolutionError, ResolutionOutput};
use crate::http::HttpClient;
use async_trait::async_trait;
use oauth2::http::{Method as OauthHttpMethod, Request as OauthHttpRequest};
use one_core::proto::http_client::HttpClient as OneCoreHttpClient;
use one_core::proto::http_client::{
    Error as OneCoreHttpError, Headers, Method, Request, RequestBuilder, Response, StatusCode,
};
use one_core::provider::did_method::DidMethod;
use one_core::provider::did_method::dto::DidDocumentDTO;
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::did_method::webvh::{DidWebVh as OneCoreDidWebVh, Params};
use one_core::provider::key_storage::KeyStorage;
use one_core::provider::key_storage::provider::KeyProvider;
use shared_types::DidValue;
use ssi::dids::document::Represented;
use ssi::dids::resolution::{Options, Output};
use std::sync::Arc;
use time::Duration;

const WEBVH_METHOD_NAME: &str = "webvh";
const DID_RESOLUTION_FORMAT: &str = "application/did+ld+json";

/// Adapts EQUS SDK's [`HttpClient`] to the one-core [`OneCoreHttpClient`] interface.
///
/// This is an internal implementation detail; callers interact only with [`HttpClient`].
#[derive(Clone)]
struct OneCoreHttpClientAdapter {
    inner: Arc<dyn HttpClient>,
}

#[async_trait]
impl OneCoreHttpClient for OneCoreHttpClientAdapter {
    fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Get, url)
    }

    fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Post, url)
    }

    fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Put, url)
    }

    fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Patch, url)
    }

    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
        _timeout: Option<Duration>,
    ) -> Result<Response, OneCoreHttpError> {
        let http_method = match method {
            Method::Get => OauthHttpMethod::GET,
            Method::Post => OauthHttpMethod::POST,
            Method::Put => OauthHttpMethod::PUT,
            Method::Patch => OauthHttpMethod::PATCH,
        };

        let mut builder = OauthHttpRequest::builder().method(http_method).uri(url);

        if let Some(ref headers) = headers {
            for (name, value) in headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
        }

        let request = builder
            .body(body.clone().unwrap_or_default())
            .map_err(|_| OneCoreHttpError::StatusCodeError(StatusCode(0)))?;

        let equs_sdk_response = self
            .inner
            .async_call(request)
            .await
            .map_err(|_| OneCoreHttpError::StatusCodeError(StatusCode(0)))?;

        let resp_headers: Headers = equs_sdk_response
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
            .collect();
        let resp_body = equs_sdk_response.body().to_vec();

        let req = Request {
            body,
            headers: headers.unwrap_or_default(),
            method,
            url: url.to_string(),
            timeout: Some(Duration::minutes(10)),
        };

        Response {
            body: resp_body,
            headers: resp_headers,
            status: StatusCode(equs_sdk_response.status().as_u16()),
            request: req,
        }
        .error_for_status()
    }
}

/// No-op [`KeyProvider`] used when only DID resolution (not creation) is needed.
struct NoopKeyProvider;

impl KeyProvider for NoopKeyProvider {
    fn get_key_storage(&self, _key_provider_id: &str) -> Option<Arc<dyn KeyStorage>> {
        None
    }
}

/// Resolver for the `did:webvh` DID method.
///
/// Wraps one-core's `DidWebVh` resolver and exposes it via the EQUS SDK [`DIDResolver`] trait so it
/// can be registered with [`crate::did::universal::UniversalResolver`].
#[derive(Clone)]
pub struct DIDWebVh {
    resolver: Arc<OneCoreDidWebVh>,
}

impl DIDWebVh {
    /// Creates a new `DIDWebVh` resolver with default parameters.
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self::with_params(http_client, Params::default())
    }

    /// Creates a new `DIDWebVh` resolver with custom [`Params`].
    ///
    /// Useful in tests to set `max_did_log_entry_check` or `resolve_to_insecure_http`.
    pub fn with_params(http_client: Arc<dyn HttpClient>, params: Params) -> Self {
        let adapter = Arc::new(OneCoreHttpClientAdapter { inner: http_client });
        let did_method_provider = Arc::new(DidMethodProviderImpl::default());
        let resolver = OneCoreDidWebVh::new(
            params,
            None,
            adapter,
            did_method_provider,
            Arc::new(NoopKeyProvider),
        );
        Self {
            resolver: Arc::new(resolver),
        }
    }
}

#[async_trait]
impl DIDResolver for DIDWebVh {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a ssi::dids::DID,
        _options: Options,
    ) -> Result<ResolutionOutput, ResolutionError> {
        let did_value: DidValue = did
            .as_str()
            .parse()
            .map_err(|e| ResolutionError::Internal(format!("Invalid DID value: {e}")))?;

        let doc = self
            .resolver
            .resolve(&did_value)
            .await
            .map_err(|e| ResolutionError::Internal(e.to_string()))?;

        let dto: DidDocumentDTO = doc.into();
        let bytes = serde_json::to_vec(&dto).map_err(|e| {
            ResolutionError::Internal(format!("Failed to serialize DID document: {e}"))
        })?;
        let ssi_doc: ssi::dids::Document = serde_json::from_slice(&bytes)
            .map_err(|e| ResolutionError::Internal(format!("Failed to parse DID document: {e}")))?;

        Ok(Output {
            document: Represented::new(ssi_doc, ssi::dids::document::representation::Options::Json),
            document_metadata: ssi::dids::document::Metadata::default(),
            metadata: ssi::dids::resolution::Metadata {
                content_type: Some(DID_RESOLUTION_FORMAT.to_string()),
            },
        })
    }

    fn method_name(&self) -> String {
        WEBVH_METHOD_NAME.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::universal::UniversalResolver;
    use crate::http::HttpClient;
    use ssi::dids::DIDResolver as SpruceResolver;

    // ── JSONL fixtures ───────────────────────────────────────────────────────
    // Each fixture is valid JSONL: one complete JSON array per line.
    // Lines are long by necessity — JSONL does not allow intra-entry newlines.

    // did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com
    // Single entry with two verification methods (auth-key-01, assert-key-01).
    const DID_SINGLE_ENTRY: &str = r#"["1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","2025-03-25T15:27:36Z",{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9","updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-03-25T15:27:36Z","proofPurpose":"authentication","challenge":"1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","proofValue":"z3YnCnQT3DPXdBrBh5DdRXFKNskeGEYVaw3Z2z7uHgJKhVaraWaYtP5V36sR4PhWKzEafyvLWX81NBMvWyYf8S1UE"}]]
"#;

    // did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com
    // Four sequential entries; resolver must return the last document state.
    const DID_LONG_LOG: &str = r#"["1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","2025-03-25T15:27:36Z",{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9","updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-03-25T15:27:36Z","proofPurpose":"authentication","challenge":"1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","proofValue":"z3YnCnQT3DPXdBrBh5DdRXFKNskeGEYVaw3Z2z7uHgJKhVaraWaYtP5V36sR4PhWKzEafyvLWX81NBMvWyYf8S1UE"}]]
["2-Qmdnj7LH4UXkRrsCty4YZ2cTQctNgV1QFDaJAH4SwjNCTZ","2025-03-25T16:27:36Z",{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9","updateKeys":["z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-03-25T16:27:36Z","proofPurpose":"authentication","challenge":"2-Qmdnj7LH4UXkRrsCty4YZ2cTQctNgV1QFDaJAH4SwjNCTZ","proofValue":"z2Vk7gJFLHRjYSKuJyYXWguYZegKAErhQjMy4nDFPTvwB2MHrMwmfTSXAJctGbJ6gywkSkBBaA7QisnEjcfcMT9Cs"}]]
["3-QmZKUb9sQtZZnVoPBmuWH78697R2ryMkx4Fnqyi85mdkYd","2025-03-25T17:27:36Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH#z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH","created":"2025-03-25T17:27:36Z","proofPurpose":"authentication","challenge":"3-QmZKUb9sQtZZnVoPBmuWH78697R2ryMkx4Fnqyi85mdkYd","proofValue":"z3cESficeEQrzt8wUrCDfzBzUZHCLFQ4nBLhkkPhrVbe8dMpwMthpGK1g3m3J8MoLo8z1RmRwDzVp6rZUvfABi2Aw"}]]
["4-QmXVv8BrCY9EYBfLhVXgLy7osRRPxchPuU1EnX5kVJXoVn","2025-03-25T18:27:36Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH#z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH","created":"2025-03-25T18:27:36Z","proofPurpose":"authentication","challenge":"4-QmXVv8BrCY9EYBfLhVXgLy7osRRPxchPuU1EnX5kVJXoVn","proofValue":"z36x93rVT536m1VLQ6BY4Zp4eoKhMxRYtZJNvjw6iBi24eKBHP3LuzfovRTNg6ySA39jtwfcpFrfTeKTnNcDPDMnD"}]]
"#;

    // did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com
    // Two entries; entry 2 sets deactivated=true.
    const DEACTIVATED: &str = r#"["1-QmNREYf7Mmy5P8GAQzpj8Yh48QyyB8wtc4NgBQWSf9eQa1","2025-05-19T12:13:13Z",{"method":"did:webvh:0.3","updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"scid":"QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ"},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com","authentication":["did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#auth-key-01","controller":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#assert-key-01","controller":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-05-19T12:13:13Z","proofPurpose":"authentication","challenge":"1-QmNREYf7Mmy5P8GAQzpj8Yh48QyyB8wtc4NgBQWSf9eQa1","proofValue":"z5FRHJPracbotV2vJAFfMFHCebifqLj5tHkZYPNCJ772Ph9nUB9ZPQe27onhS7PtBEn2wWzYJQ8SCkQJfZvnUASYA"}]]
["2-QmVZjo7pHNxXgvt2DED637NJtY9EkiQLudZ32C9kMvReRa","2025-05-19T12:13:27Z",{"method":"did:webvh:0.3","updateKeys":[],"scid":"QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ","deactivated":true},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com","authentication":["did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#auth-key-01","controller":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#assert-key-01","controller":"did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-05-19T12:13:27Z","proofPurpose":"authentication","challenge":"2-QmVZjo7pHNxXgvt2DED637NJtY9EkiQLudZ32C9kMvReRa","proofValue":"z2Gh29jwNFDF7qiqCVf5YiTSGbVeCdruHgqbr9VqojWYLB45ArQsQcmGv54b57JvWa1yqkThv3Srp4NAoWm5rJ63k"}]]
"#;

    // did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com
    // proofValue has one character corrupted (S1UE → S1UB), making the signature invalid.
    const INVALID_SIG: &str = r#"["1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","2025-03-25T15:27:36Z",{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9","updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-03-25T15:27:36Z","proofPurpose":"authentication","challenge":"1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","proofValue":"z3YnCnQT3DPXdBrBh5DdRXFKNskeGEYVaw3Z2z7uHgJKhVaraWaYtP5V36sR4PhWKzEafyvLWX81NBMvWyYf8S1UB"}]]
"#;

    // did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com
    // Four entries; entry 4 versionId hash (QmZKUb9...) does not match its computed content hash.
    const ENTRY_HASH_MISMATCH: &str = r#"["1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","2025-03-25T15:27:36Z",{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9","updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-03-25T15:27:36Z","proofPurpose":"authentication","challenge":"1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","proofValue":"z3YnCnQT3DPXdBrBh5DdRXFKNskeGEYVaw3Z2z7uHgJKhVaraWaYtP5V36sR4PhWKzEafyvLWX81NBMvWyYf8S1UE"}]]
["2-Qmdnj7LH4UXkRrsCty4YZ2cTQctNgV1QFDaJAH4SwjNCTZ","2025-03-25T16:27:36Z",{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9","updateKeys":["z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","created":"2025-03-25T16:27:36Z","proofPurpose":"authentication","challenge":"2-Qmdnj7LH4UXkRrsCty4YZ2cTQctNgV1QFDaJAH4SwjNCTZ","proofValue":"z2Vk7gJFLHRjYSKuJyYXWguYZegKAErhQjMy4nDFPTvwB2MHrMwmfTSXAJctGbJ6gywkSkBBaA7QisnEjcfcMT9Cs"}]]
["3-QmZKUb9sQtZZnVoPBmuWH78697R2ryMkx4Fnqyi85mdkYd","2025-03-25T17:27:36Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}},{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"6TlGS6xtcDchAUw08wG9RcUWT33Xxmtmo6bNpclDegc","y":"5uPTP0Oo-60GYEEx-lFnax4WeC9YUZx5E2kV3toPthY","kid":"assert-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH#z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH","created":"2025-03-25T17:27:36Z","proofPurpose":"authentication","challenge":"3-QmZKUb9sQtZZnVoPBmuWH78697R2ryMkx4Fnqyi85mdkYd","proofValue":"z3cESficeEQrzt8wUrCDfzBzUZHCLFQ4nBLhkkPhrVbe8dMpwMthpGK1g3m3J8MoLo8z1RmRwDzVp6rZUvfABi2Aw"}]]
["4-QmZKUb9sQtZZnVoPBmuWH78697R2ryMkx4Fnqyi85mdkYd","2025-03-25T18:27:36Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01","controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs","y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}}],"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH#z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH","created":"2025-03-25T18:27:36Z","proofPurpose":"authentication","challenge":"4-QmZKUb9sQtZZnVoPBmuWH78697R2ryMkx4Fnqyi85mdkYd","proofValue":"z53A6isgVbW5QYnfP9tZM2aKTnVJYUBFgNuGfA9N3hyBZRv6CzGe9S1yqA5xBBsMShBNo3AYNW4d6MDXKMwShT1QZ"}]]
"#;

    // ── Test HTTP client doubles ─────────────────────────────────────────────

    /// Returns a canned body with a given status for any request.
    #[derive(Clone)]
    struct StubHttpClient {
        body: &'static [u8],
        status: u16,
    }

    impl StubHttpClient {
        fn ok(body: &'static [u8]) -> Arc<Self> {
            Arc::new(Self { body, status: 200 })
        }

        fn error(status: u16) -> Arc<Self> {
            Arc::new(Self { body: b"", status })
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for StubHttpClient {
        async fn async_call(
            &self,
            _: oauth2::HttpRequest,
        ) -> crate::http::Result<oauth2::HttpResponse> {
            let mut response = oauth2::HttpResponse::new(self.body.to_vec());
            *response.status_mut() =
                oauth2::http::StatusCode::from_u16(self.status).map_err(|e| {
                    crate::http::HttpSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;
            Ok(response)
        }
    }

    /// Always returns a network-level error.
    #[derive(Clone)]
    struct FailingHttpClient;

    #[async_trait::async_trait]
    impl HttpClient for FailingHttpClient {
        async fn async_call(
            &self,
            _: oauth2::HttpRequest,
        ) -> crate::http::Result<oauth2::HttpResponse> {
            Err(crate::http::HttpSnafu {
                details: "connection refused".to_string(),
            }
            .build())
        }
    }

    // ── Positive tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn didwebvh_resolves_single_entry_log() {
        let resolver = DIDWebVh::new(StubHttpClient::ok(DID_SINGLE_ENTRY.as_bytes()));
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();

        let output = resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();

        assert_eq!(
            output.document.document().id.as_str(),
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com"
        );
        assert!(output.metadata.content_type.is_some());
    }

    #[tokio::test]
    async fn didwebvh_resolves_multi_entry_log_returns_last_state() {
        let resolver = DIDWebVh::new(StubHttpClient::ok(DID_LONG_LOG.as_bytes()));
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();

        let output = resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();

        assert_eq!(
            output.document.document().id.as_str(),
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com"
        );
        assert!(output.metadata.content_type.is_some());
    }

    #[tokio::test]
    async fn didwebvh_resolves_via_universal_resolver() {
        let mut resolver = UniversalResolver::default();
        resolver
            .add_resolver(DIDWebVh::new(StubHttpClient::ok(
                DID_SINGLE_ENTRY.as_bytes(),
            )))
            .unwrap();

        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();

        let output = resolver.resolve(did).await.unwrap();
        assert!(output.metadata.content_type.is_some());
        assert_eq!(
            output.document.id.as_did().to_string(),
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com"
        );
    }

    #[tokio::test]
    #[should_panic(expected = "MethodNotSupported(\"webvh\")")]
    async fn didwebvh_universal_resolver_does_not_know_webvh_before_registration() {
        let resolver = UniversalResolver::default();
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();
        resolver.resolve(did).await.unwrap();
    }

    // ── Negative tests ───────────────────────────────────────────────────────

    #[tokio::test]
    #[should_panic(expected = "HTTP status code is error: 0")]
    async fn didwebvh_resolution_fails_on_http_error() {
        let resolver = DIDWebVh::new(Arc::new(FailingHttpClient));
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();
        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "HTTP status code is error: 404")]
    async fn didwebvh_resolution_fails_on_http_404() {
        let resolver = DIDWebVh::new(StubHttpClient::error(404));
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();
        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "deactivated")]
    async fn didwebvh_resolution_fails_on_deactivated_did() {
        let resolver = DIDWebVh::new(StubHttpClient::ok(DEACTIVATED.as_bytes()));
        let did = ssi::dids::DID::new(
            "did:webvh:QmWGkYd9QNJ7ug59s9Dek5q4oWwxnWJZ95tyGXk4mpRqbJ:example.com",
        )
        .unwrap();
        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid signature")]
    async fn didwebvh_resolution_fails_on_invalid_signature() {
        let resolver = DIDWebVh::new(StubHttpClient::ok(INVALID_SIG.as_bytes()));
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();
        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Entry hash mismatch")]
    async fn didwebvh_resolution_fails_on_entry_hash_mismatch() {
        let resolver = DIDWebVh::new(StubHttpClient::ok(ENTRY_HASH_MISMATCH.as_bytes()));
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();
        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "log has 4 entries which is more than the max allowed length (2)")]
    async fn didwebvh_resolution_fails_when_max_entries_exceeded() {
        let params = Params {
            max_did_log_entry_check: Some(2),
            ..Params::default()
        };
        let resolver = DIDWebVh::with_params(StubHttpClient::ok(DID_LONG_LOG.as_bytes()), params);
        let did = ssi::dids::DID::new(
            "did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",
        )
        .unwrap();
        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "MethodNotSupported(\"webvh\")")]
    async fn didwebvh_resolution_fails_on_wrong_did_method() {
        let resolver = UniversalResolver::default();
        let did = ssi::dids::DID::new("did:webvh:example.com").unwrap();
        resolver.resolve(did).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Method already exists")]
    async fn universal_resolver_rejects_duplicate_webvh_registration() {
        let mut resolver = UniversalResolver::default();
        resolver
            .add_resolver(DIDWebVh::new(StubHttpClient::ok(b"")))
            .unwrap();
        resolver
            .add_resolver(DIDWebVh::new(StubHttpClient::ok(b"")))
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "missing domain segment")]
    async fn didwebvh_resolution_fails_on_did_with_unparseable_method_specific_id() {
        // The one-core resolver rejects a did:webvh whose method-specific id is
        // not in `scid:domain` form before any HTTP I/O is performed.
        let resolver = DIDWebVh::new(StubHttpClient::ok(b""));
        let did = ssi::dids::DID::new("did:webvh:short").unwrap();

        resolver
            .resolve_representation(did, Options::default())
            .await
            .unwrap();
    }
}
