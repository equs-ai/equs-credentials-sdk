use url::Url;

use crate::did::universal::UniversalResolver;
use crate::didcomm::agent::{Agent, AgentConfig};
use crate::didcomm::connection::in_mem::InMemConnectionService;
use crate::didcomm::transport::http::HttpTransport;
use crate::didcomm::transport::mock::MockTransport;
use crate::inmem::kms::{KeyHandle, LocalKms};
use crate::reqwest::builder::ReqwestClientBuilder;

pub fn test_agent() -> (
    Agent<LocalKms, KeyHandle, InMemConnectionService>,
    MockTransport,
) {
    // Create agent config
    let config = AgentConfig {
        domain: Url::parse("http://test-agent.example.com").unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8000").unwrap(),
        label: "Test Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let did_resolver = UniversalResolver::default();
    let kms = LocalKms::new();
    let http_transport = MockTransport::new(config.endpoint.clone(), &kms, &did_resolver);

    let connection_service = InMemConnectionService::new();

    let agent = Agent::new(
        config,
        kms,
        did_resolver,
        connection_service,
        http_transport.clone(),
        http_transport.clone(),
    );

    (agent, http_transport)
}

pub fn setup_agent(config: AgentConfig) -> Agent<LocalKms, KeyHandle, InMemConnectionService> {
    let kms = LocalKms::new();
    let did_resolver = UniversalResolver::default();

    let http_transport = HttpTransport::new(
        config.endpoint.clone(),
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    );

    let connection_service = InMemConnectionService::new();

    Agent::new(
        config,
        kms,
        did_resolver,
        connection_service,
        http_transport.clone(),
        http_transport,
    )
}
