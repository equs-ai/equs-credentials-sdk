use crate::utils::fixtures::oid4vp::{
    Oid4VpTestCase, create_vc, generate_did_key_and_vm, single_jsonld_presentation_case,
};
use async_trait::async_trait;
use equs_sdk::did::didkey::DIDKey;
use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::did::{DID, DIDResolver};
use equs_sdk::didcomm::agent::{Agent, AgentConfig};
use equs_sdk::didcomm::connection::in_mem::InMemConnectionService;
use equs_sdk::didcomm::core::envelope::Message;
use equs_sdk::didcomm::core::protocol;
use equs_sdk::didcomm::core::protocol::Protocol;
use equs_sdk::didcomm::core::protocol::message_handler::MessageHandler;
use equs_sdk::didcomm::protocol::aries::common::message::status::Status;
use equs_sdk::didcomm::protocol::aries::issuance::holder::IssuanceHolder;
use equs_sdk::didcomm::protocol::aries::issuance::holder::states::IssuanceHolderState;
use equs_sdk::didcomm::protocol::aries::issuance::issuer::states::IssuerState;
use equs_sdk::didcomm::protocol::aries::issuance::issuer::{CredentialInfo, Issuer};
use equs_sdk::didcomm::protocol::aries::present_proof::holder::PresentationHolder;
use equs_sdk::didcomm::protocol::aries::present_proof::holder::states::PresentationHolderState;
use equs_sdk::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use equs_sdk::didcomm::protocol::aries::present_proof::message::proof_request::ProofRequest;
use equs_sdk::didcomm::protocol::aries::present_proof::verifier::Verifier;
use equs_sdk::didcomm::protocol::aries::present_proof::verifier::states::VerifierState;
use equs_sdk::didcomm::protocol::aries::problem_report::PROBLEM_REPORT;
use equs_sdk::didcomm::protocol::aries::problem_report::message::{
    ProblemReport, ProblemReportCode,
};
use equs_sdk::didcomm::protocol::outofband::{InvitationConfig, OutOfBandV2Protocol};
use equs_sdk::didcomm::transport::http::HttpTransport;
use equs_sdk::inmem::kms::{KeyHandle, LocalKms};
use equs_sdk::inmem::storage::InMemStorage;
use equs_sdk::inmem::vault::InMemVault;
use equs_sdk::kms;
use equs_sdk::kms::{KeyType, Kms};
use equs_sdk::reqwest::builder::ReqwestClientBuilder;
use equs_sdk::vault::Vault;
use equs_sdk::vc::core::KeyMetadata;
use equs_sdk::vc::{Credential, CredentialMetadata};
use serde_json::json;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use url::Url;

#[tokio::test]
async fn test_issuance() {
    let issuer_agent_config = AgentConfig {
        domain: Url::parse("http://government-agent.example.com").unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8010").unwrap(),
        label: "Government Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let issuer_agent = setup_agent(issuer_agent_config.clone(), None).await;
    issuer_agent.start().await.unwrap();

    println!("Issuer Agent started at {}", issuer_agent_config.endpoint);

    let issuer = Issuer::new(
        &issuer_agent,
        InMemStorage::<String, IssuerState>::new(),
        KeyType::P256,
    )
    .await
    .unwrap();

    println!("1. Issuer creates a credential offer");
    let credential_info = credential_info(&issuer_agent).await;
    let thread_id = issuer.create_offer(credential_info).await.unwrap();

    let (_, iss_observable) = issuer.observe_state(thread_id.to_owned()).await;

    let issuer_state = issuer.get_state(&thread_id).await.unwrap();
    assert!(matches!(issuer_state, IssuerState::Initial(_)));
    if let IssuerState::Initial(state) = issuer_state {
        println!("{}", serde_json::to_string_pretty(&state.offer).unwrap());
    }
    println!("===============================================================================");

    println!("2. Issuer creates an invitation");
    let invitation_config = InvitationConfig {
        key_type: KeyType::P256,
        label: "Issuer's Invitation".to_string(),
        goal: "Credential Offer".to_string(),
        goal_code: "offer-credential".to_string(),
        attachments: vec![],
    };

    let invitation_url = issuer
        .create_invitation(&thread_id, invitation_config)
        .await
        .unwrap();

    let issuer_state = iss_observable.next().await.unwrap();
    println!("{invitation_url}");
    assert!(matches!(issuer_state, IssuerState::OfferSent(_)));
    println!("===============================================================================");

    let holder_config = AgentConfig {
        domain: Url::parse("http://alice-agent.example.com").unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8020").unwrap(),
        label: "Alice Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let holder_agent = setup_agent(holder_config.clone(), None).await;
    holder_agent.start().await.unwrap();

    println!("Holder Agent started at {}", holder_config.endpoint);

    let (_, hld_key_metadata, _) = create_did_and_key_metadata(holder_agent.kms()).await;

    println!("3. Holder accepts the invitation");

    let mut holder = IssuanceHolder::new(
        invitation_url,
        hld_key_metadata,
        &holder_agent,
        InMemStorage::<String, IssuanceHolderState>::new(),
        InMemVault::new(),
        KeyType::P256,
    )
    .await
    .unwrap();
    println!("===============================================================================");

    let (_, hls_observable) = holder.observe_state().await;

    println!("4. Holder sends credential request");
    holder.send_credential_request().await.unwrap();

    let holder_state = hls_observable.next().await.unwrap();
    assert!(matches!(holder_state, IssuanceHolderState::RequestSent(_)));
    println!("===============================================================================");

    let issuer_state = iss_observable.next().await.unwrap();
    println!("5. Issuer received credential request");
    assert!(matches!(issuer_state, IssuerState::RequestReceived(_)));
    if let IssuerState::RequestReceived(state) = issuer_state {
        println!("{}", serde_json::to_string_pretty(&state.request).unwrap());
    }
    println!("===============================================================================");

    println!("6. Issuer sends credential");
    issuer.send_credential(&thread_id).await.unwrap();

    let issuer_state = iss_observable.next().await.unwrap();
    assert!(matches!(issuer_state, IssuerState::CredentialSent(_)));
    println!("===============================================================================");

    let holder_state = hls_observable.next().await.unwrap();
    println!("7. Holder received credential");
    assert!(matches!(holder_state, IssuanceHolderState::Finished(_)));
    if let IssuanceHolderState::Finished(state) = holder_state {
        println!(
            "{}",
            serde_json::to_string_pretty(&state.credential).unwrap()
        );
    }
    println!("===============================================================================");

    let issuer_state = iss_observable.next().await.unwrap();
    println!("8. Issuer received acknowledgement");
    assert!(matches!(issuer_state, IssuerState::Finished(_)));
    println!("===============================================================================");

    issuer_agent.stop().await.unwrap();
    holder_agent.stop().await.unwrap();
}

#[tokio::test]
async fn test_presentation() {
    let verifier_url = "http://business-agent.example.com".to_string();
    let verifier_agent_config = AgentConfig {
        domain: Url::parse(&verifier_url).unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8011").unwrap(),
        label: "Business Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let verifier_agent = setup_agent(verifier_agent_config.clone(), None).await;
    verifier_agent.start().await.unwrap();

    println!(
        "Verifier Agent started at {}",
        verifier_agent_config.endpoint
    );

    let verifier = Verifier::new(
        &verifier_agent,
        InMemStorage::<String, VerifierState>::new(),
        KeyType::P256,
        verifier_url,
    )
    .await
    .unwrap();

    let kms = LocalKms::new();
    let test_case = single_jsonld_presentation_case();
    let presentation_definition = test_case.presentation_definition.to_owned();
    let (credential, metadata) = create_credential(test_case, &kms).await;

    let vault = InMemVault::new();
    vault.store_credential(credential, &metadata).await.unwrap();

    println!("1. Verifier creates a presentation request");
    let proof_request = ProofRequest::new(
        serde_json::from_value(serde_json::to_value(presentation_definition).unwrap()).unwrap(),
    );
    let thread_id = verifier
        .create_presentation_request(proof_request)
        .await
        .unwrap();
    let presentation_request = verifier
        .get_presentation_request(thread_id.clone())
        .await
        .unwrap();

    let (_, verifier_observable) = verifier.observe_state(thread_id.to_owned()).await;

    let verifier_state = verifier.get_state(&thread_id).await.unwrap();
    assert!(matches!(verifier_state, VerifierState::Initiated(_)));
    if let VerifierState::Initiated(state) = verifier_state {
        println!(
            "{}",
            serde_json::to_string_pretty(&state.presentation_request).unwrap()
        );
    }
    println!("===============================================================================");

    println!("2. Verifier creates an invitation");
    let invitation_config = InvitationConfig {
        key_type: KeyType::P256,
        label: "Verifier's Invitation".to_string(),
        goal: "Presentation request".to_string(),
        goal_code: "presentation-request".to_string(),
        attachments: vec![presentation_request.try_into().unwrap()],
    };

    let invitation_url = verifier
        .create_invitation(thread_id.clone(), invitation_config)
        .await
        .unwrap();

    let verifier_state = verifier_observable.next().await.unwrap();
    println!("{invitation_url}");
    assert!(matches!(
        verifier_state,
        VerifierState::PresentationRequestSent(_)
    ));
    println!("===============================================================================");

    let prover_config = AgentConfig {
        domain: Url::parse("http://alice-agent.example.com").unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8021").unwrap(),
        label: "Alice Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let prover_agent = setup_agent(prover_config.clone(), Some(kms)).await;
    prover_agent.start().await.unwrap();

    println!("Prover Agent started at {}", prover_config.endpoint);

    let (_, prover_key_metadata, _) = create_did_and_key_metadata(prover_agent.kms()).await;

    println!("3. Prover accepts the invitation");

    let prover = PresentationHolder::new(
        &prover_agent,
        prover_key_metadata,
        InMemStorage::<String, PresentationHolderState>::new(),
        vault,
        invitation_url,
        KeyType::P256,
        thread_id,
    )
    .await
    .unwrap();
    println!("===============================================================================");

    let (_, prover_observable) = prover.observe_state().await;

    println!("4. Prover set presentation");
    prover.prepare_presentation().await.unwrap();

    let prover_state = prover_observable.next().await.unwrap();
    assert!(matches!(
        prover_state,
        PresentationHolderState::PresentationPrepared(_)
    ));
    println!("===============================================================================");

    println!("5. Prover sends presentation");
    prover.send_presentation().await.unwrap();

    let prover_state = prover_observable.next().await.unwrap();
    assert!(matches!(prover_state, PresentationHolderState::Finished(_)));
    println!("===============================================================================");

    let verifier_state = verifier_observable.next().await.unwrap();
    println!("6. Verifier received presentation");
    assert!(matches!(verifier_state, VerifierState::Finished(_)));
    if let VerifierState::Finished(state) = verifier_state {
        println!(
            "{}",
            serde_json::to_string_pretty(&state.presentation).unwrap()
        );
    }
    println!("===============================================================================");

    verifier_agent.stop().await.unwrap();
    prover_agent.stop().await.unwrap();
}

#[tokio::test]
async fn test_presentation_replayed_to_another_verifier_is_rejected() {
    let test_case = single_jsonld_presentation_case();
    let presentation_definition = test_case.presentation_definition.to_owned();
    let kms = LocalKms::new();
    let (credential, metadata) = create_credential(test_case, &kms).await;
    let vault = InMemVault::new();
    vault.store_credential(credential, &metadata).await.unwrap();

    let (verifier_1_agent, verifier_1, thread_1, invitation_1) =
        verifier_with_invitation("http://127.0.0.1:8012", &presentation_definition).await;
    let (verifier_2_agent, verifier_2, thread_2, invitation_2) =
        verifier_with_invitation("http://127.0.0.1:8013", &presentation_definition).await;

    let holder_agent = started_agent("http://127.0.0.1:8022", Some(kms)).await;
    let (_, key_metadata, _) = create_did_and_key_metadata(holder_agent.kms()).await;
    let holder = PresentationHolder::new(
        &holder_agent,
        key_metadata,
        InMemStorage::<String, PresentationHolderState>::new(),
        vault,
        invitation_1,
        KeyType::P256,
        thread_1.to_owned(),
    )
    .await
    .unwrap();
    let (_, verifier_1_states) = verifier_1.observe_state(thread_1.to_owned()).await;
    holder.prepare_presentation().await.unwrap();
    holder.send_presentation().await.unwrap();

    let VerifierState::Finished(accepted) = verifier_1_states.next().await.unwrap() else {
        panic!("verifier 1 did not finish");
    };
    assert_eq!(accepted.status, Status::Success);
    let accepted = accepted.presentation.unwrap();

    let replayer_agent = started_agent("http://127.0.0.1:8023", None).await;
    let (reports_tx, mut reports) = tokio::sync::mpsc::unbounded_channel();
    replayer_agent
        .register_protocol(PresentProofReports(ReportSink(reports_tx)))
        .await
        .unwrap();
    let oob = OutOfBandV2Protocol::new(&replayer_agent);
    let connection = oob
        .accept_invitation(
            oob.parse_invitation(invitation_2.as_str()).unwrap(),
            KeyType::P256,
        )
        .await
        .unwrap();
    let mut replayed: Message = Presentation::create()
        .add_attachments(accepted.attachments)
        .set_thread_id(&thread_2)
        .try_into()
        .unwrap();
    replayer_agent
        .send_message(&mut replayed, &connection.id)
        .await
        .unwrap();

    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await;
    let verifier_2_state = verifier_2.get_state(&thread_2).await.unwrap();
    assert!(
        matches!(verifier_2_state, VerifierState::PresentationRequestSent(_)),
        "verifier 2 accepted a replayed presentation: {verifier_2_state:?}"
    );
    let report: ProblemReport = report
        .expect("verifier 2 sent no problem report")
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        report.body.code,
        ProblemReportCode::InvalidPresentation.code()
    );

    for agent in [
        verifier_1_agent,
        verifier_2_agent,
        holder_agent,
        replayer_agent,
    ] {
        agent.stop().await.unwrap();
    }
}

/// Receives the `present-proof` problem reports a verifier sends back.
struct PresentProofReports(ReportSink);

impl Protocol for PresentProofReports {
    fn protocol_name(&self) -> &'static str {
        "present-proof"
    }

    fn protocol_version(&self) -> &'static str {
        "3.0"
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        vec![&self.0]
    }
}

struct ReportSink(UnboundedSender<Message>);

#[async_trait]
impl MessageHandler for ReportSink {
    fn supported_message_types(&self) -> &[&str] {
        &[PROBLEM_REPORT]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        self.0.send(msg).unwrap();
        Ok(())
    }
}

async fn verifier_with_invitation(
    endpoint: &str,
    presentation_definition: &impl serde::Serialize,
) -> (
    Agent<LocalKms, KeyHandle, InMemConnectionService>,
    Verifier<LocalKms, KeyHandle, InMemConnectionService, InMemStorage<String, VerifierState>>,
    String,
    Url,
) {
    let agent = started_agent(endpoint, None).await;
    let verifier = Verifier::new(
        &agent,
        InMemStorage::<String, VerifierState>::new(),
        KeyType::P256,
        endpoint.to_owned(),
    )
    .await
    .unwrap();

    let proof_request = ProofRequest::new(
        serde_json::from_value(serde_json::to_value(presentation_definition).unwrap()).unwrap(),
    );
    let thread_id = verifier
        .create_presentation_request(proof_request)
        .await
        .unwrap();
    let invitation_config = InvitationConfig {
        key_type: KeyType::P256,
        label: "Verifier's Invitation".to_string(),
        goal: "Presentation request".to_string(),
        goal_code: "presentation-request".to_string(),
        attachments: vec![],
    };
    let invitation = verifier
        .create_invitation(thread_id.to_owned(), invitation_config)
        .await
        .unwrap();

    (agent, verifier, thread_id, invitation)
}

async fn started_agent(
    endpoint: &str,
    kms: Option<LocalKms>,
) -> Agent<LocalKms, KeyHandle, InMemConnectionService> {
    let config = AgentConfig {
        domain: Url::parse(endpoint).unwrap(),
        endpoint: Url::parse(endpoint).unwrap(),
        label: endpoint.to_owned(),
        didcomm_scheme: Some("didcomm".to_string()),
    };
    let agent = setup_agent(config, kms).await;
    agent.start().await.unwrap();
    agent
}

async fn credential_info(
    agent: &Agent<LocalKms, KeyHandle, InMemConnectionService>,
) -> CredentialInfo {
    let (_, iss_key_metadata) =
        create_did_and_key_metadata_by_key_type(agent.kms(), KeyType::Ed25519).await;

    let claims = json!({
        "type": ["PermanentResident", "Person"],
        "givenName": "JANE",
        "familyName": "SMITH",
        "gender": "Female",
        "image": "data:image/png;base64,iVBORw0KGgoAA...Jggg==",
        "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
        "residentSince": "2015-01-01",
        "commuterClassification": "C1",
        "birthCountry": "Arcadia",
        "birthDate": "1978-07-17"
    })
    .try_into()
    .unwrap();

    let context = vec![
        "https://www.w3.org/2018/credentials/v1".to_string(),
        "https://w3id.org/citizenship/v1".to_string(),
    ];
    let types = vec!["PermanentResidentCard".to_string()];

    CredentialInfo::new(context, types, claims, 365, iss_key_metadata, None).unwrap()
}
async fn setup_agent(
    config: AgentConfig,
    kms: Option<LocalKms>,
) -> Agent<LocalKms, KeyHandle, InMemConnectionService> {
    let did_resolver = UniversalResolver::default();

    let http_transport = HttpTransport::new(
        config.endpoint.clone(),
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    );

    let connection_service = InMemConnectionService::new();

    Agent::new(
        config,
        kms.unwrap_or(LocalKms::new()),
        did_resolver,
        connection_service,
        http_transport.clone(),
        http_transport,
    )
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata, KeyHandle) {
    let (kid, kh) = kms
        .create_and_handle(KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh.to_owned()).unwrap();

    let did_url = UniversalResolver::default()
        .resolve_into_any_verification_method(ssi::dids::DID::new(did.as_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: did_url.to_string(),
        },
        kh,
    )
}

async fn create_did_and_key_metadata_by_key_type(
    kms: &LocalKms,
    kt: KeyType,
) -> (DID, KeyMetadata) {
    let (kid, kh) = kms
        .create_and_handle(kt, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh).unwrap();

    let did_url = UniversalResolver::default()
        .resolve_into_any_verification_method(ssi::dids::DID::new(did.as_bytes()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: did_url.to_string(),
        },
    )
}

async fn create_credential(
    mut test_case: Oid4VpTestCase,
    kms: &LocalKms,
) -> (Credential, CredentialMetadata) {
    let (holder_key_metadata, holder_kh) = generate_did_key_and_vm(kms).await;

    let credential = test_case.credentials.drain(..).next().unwrap();
    create_vc(
        credential.format,
        &holder_key_metadata.did_url,
        holder_key_metadata.kid.clone(),
        holder_kh.clone(),
        credential.claims.clone(),
    )
    .await
}
