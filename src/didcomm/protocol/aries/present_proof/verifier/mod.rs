use crate::did::universal::UniversalResolver;
use crate::didcomm::agent::Agent;
use crate::didcomm::connection;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::event_emitter::{EventEmitter, EventObservable, Subscription};
use crate::didcomm::core::key_mutex::KeyMutex;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::empty::EMPTY;
use crate::didcomm::protocol::aries::empty::protocol::EmptyProtocol;
use crate::didcomm::protocol::aries::present_proof::message::VerifierMessages;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::message::proof_request::ProofRequest;
use crate::didcomm::protocol::aries::present_proof::protocol::PresentationProtocol;
use crate::didcomm::protocol::aries::present_proof::verifier::state_machine::VerifierSM;
use crate::didcomm::protocol::aries::present_proof::verifier::states::{
    InitialState, VerifierState,
};
use crate::didcomm::protocol::aries::present_proof::{
    AgentSnafu, ConnectionSnafu, InvalidStateSnafu, OOBSnafu, PRESENTATION, Result, StorageSnafu,
};
use crate::didcomm::protocol::aries::problem_report::PROBLEM_REPORT;
use crate::didcomm::protocol::aries::problem_report::protocol::ProblemReportProtocol;
use crate::didcomm::protocol::outofband::{InvitationConfig, OutOfBandV2Protocol};
use crate::kms::{KeyHandle, KeyType, Kms};
use crate::storage::Storage;
use crate::vc::core::VerifierService;
use async_trait::async_trait;
use snafu::{IntoError, ResultExt};
use tracing::debug;
use url::Url;

mod state_machine;
pub mod states;

#[derive(Clone)]
pub struct Verifier<KMS, KH, C, S>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
    S: Storage<String, VerifierState> + Clone + 'static,
{
    agent: Agent<KMS, KH, C>,
    storage: S,
    event_emitter: EventEmitter<String, VerifierState>,
    oob: OutOfBandV2Protocol<KMS, KH, C>,
    connection_key_type: KeyType,
    key_mutex: KeyMutex,

    verifier_service: VerifierService,
}

impl<KMS, KH, C, S> Verifier<KMS, KH, C, S>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
    S: Storage<String, VerifierState> + Clone + 'static,
{
    pub async fn new(
        agent: &Agent<KMS, KH, C>,
        storage: S,
        connection_key_type: KeyType,
        verifier_id: String,
    ) -> Result<Verifier<KMS, KH, C, S>> {
        debug!("Creating credential Verifier");

        let verifier_service = VerifierService::new(&verifier_id, UniversalResolver::default());

        let verifier = Verifier {
            agent: agent.to_owned(),
            storage,
            event_emitter: EventEmitter::new(),
            oob: OutOfBandV2Protocol::new(agent),
            connection_key_type,
            key_mutex: KeyMutex::new(),
            verifier_service,
        };

        let present_proof_protocol = PresentationProtocol::new_with_verifier(verifier.to_owned());
        agent
            .register_protocol(present_proof_protocol)
            .await
            .context(AgentSnafu)?;

        let problem_report_protocol = ProblemReportProtocol::new(Box::new(verifier.to_owned()));
        agent
            .register_protocol(problem_report_protocol)
            .await
            .context(AgentSnafu)?;

        let empty_protocol = EmptyProtocol::new(Box::new(verifier.to_owned()));
        agent
            .register_protocol(empty_protocol)
            .await
            .context(AgentSnafu)?;

        Ok(verifier)
    }

    pub async fn create_invitation(
        &self,
        presentation_request_id: String,
        mut invitation_config: InvitationConfig,
    ) -> Result<Url> {
        let presentation_request = self
            .get_presentation_request(presentation_request_id.to_owned())
            .await?;

        invitation_config
            .attachments
            .push(presentation_request.try_into()?);

        let (url, connection) = self
            .oob
            .create_invitation(invitation_config)
            .await
            .context(OOBSnafu)?;

        self.step(
            presentation_request_id,
            VerifierMessages::SendPresentationRequest(connection),
        )
        .await?;

        Ok(url)
    }

    pub async fn create_presentation_request(&self, proof_request: ProofRequest) -> Result<String> {
        let presentation_request =
            PresentationRequest::new().add_attachment(proof_request.try_into()?);

        let pr_id = presentation_request.id.to_string();

        self.storage
            .put(
                pr_id.to_string(),
                VerifierState::Initiated(InitialState {
                    presentation_request,
                }),
            )
            .await
            .context(StorageSnafu)?;
        Ok(pr_id)
    }

    pub async fn get_state(&self, id: &String) -> Result<VerifierState> {
        self.storage
            .get(id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })
    }

    pub async fn get_presentation_request(&self, id: String) -> Result<PresentationRequest> {
        let verifier_sm = self.verifier_sm(id).await?;

        verifier_sm.get_presentation_request()
    }

    pub async fn step(&self, id: String, message: VerifierMessages) -> Result<()> {
        let guard = self.key_mutex.lock(&id).await;

        let verifier_sm = self
            .verifier_sm(id.to_owned())
            .await?
            .handle_message(message)
            .await?;

        self.storage
            .put(id.to_owned(), verifier_sm.state().to_owned())
            .await
            .context(StorageSnafu)?;

        self.event_emitter
            .emit(id.to_owned(), verifier_sm.state().to_owned())
            .await;

        Ok(())
    }

    pub async fn observe_state(
        &self,
        id: String,
    ) -> (Subscription, EventObservable<VerifierState>) {
        self.event_emitter.to_owned().observe(id).await
    }

    async fn verifier_sm(&self, id: String) -> Result<VerifierSM<KMS, KH, C>> {
        let state = self
            .storage
            .get(&id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })?;

        Ok(VerifierSM::new(
            state,
            self.agent.to_owned(),
            self.verifier_service.to_owned(),
        ))
    }

    async fn establish_connection(&self, id: String, their_did: Option<String>) -> Result<()> {
        let sm = self.verifier_sm(id.to_owned()).await?;

        let connection_id = sm.get_connection_id().ok_or_else(|| {
            ConnectionSnafu.into_error(connection::Error::ConnectionNotFound { id: id.to_string() })
        })?;

        self.oob
            .establish_connection(
                connection_id,
                their_did,
                self.connection_key_type.to_owned(),
            )
            .await
            .context(OOBSnafu)
    }
}

#[async_trait]
impl<KMS, KH, C, S> MessageHandler for Verifier<KMS, KH, C, S>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
    S: Storage<String, VerifierState> + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &[PRESENTATION, PROBLEM_REPORT, EMPTY]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        let their_did = msg.from.to_owned();

        let verifier_message = msg.try_into()?;

        let id = match verifier_message {
            VerifierMessages::SendPresentationRequest(ref connection_record) => {
                connection_record.thread_id.to_owned()
            }
            VerifierMessages::PresentationReceived(ref presentation) => presentation
                .thread
                .to_owned()
                .and_then(|thread| thread.thid),
            VerifierMessages::PresentationRejectReceived(ref report) => {
                report.thread.to_owned().and_then(|thread| thread.thid)
            }
            ref state => protocol::Snafu {
                details: format!("Invalid Verifier Message: {:?}", state),
            }
            .fail()?,
        };

        // TODO: Should return ProblemReport
        let id = id.ok_or_else(|| {
            protocol::Snafu {
                details: "Missing thread ID field in DIDComm message",
            }
            .build()
        })?;

        self.establish_connection(id.to_owned(), their_did)
            .await
            .map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        self.step(id, verifier_message).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(())
    }
}
