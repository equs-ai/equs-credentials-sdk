use crate::didcomm::agent::Agent;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_type::MessageType;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::holder::states::PresentationHolderState;
use crate::didcomm::protocol::aries::present_proof::message::HolderMessages;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::message::proof_request::ProofRequest;
use crate::didcomm::protocol::aries::present_proof::{
    AgentSnafu, InvalidCredentialRequestSnafu, InvalidStateSnafu, ParseSnafu,
    PresentationDefinitionParseSnafu, holder_binder,
};
use crate::didcomm::protocol::aries::present_proof::{CreatePresentationSnafu, Result};
use crate::didcomm::protocol::aries::problem_report::message::{
    ProblemReport, ProblemReportCode, Reason,
};
use crate::kms::{KeyHandle, Kms};
use crate::vc::core::{Holder, KeyMetadata};
use crate::vc::presentation_exchange::split_to_inputs_for_pd;
use snafu::{OptionExt, ResultExt};
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// A state machine that tracks the evolution of states for a Holder during
/// the Present Proof protocol.
#[derive(Clone)]
pub struct HolderSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    state: PresentationHolderState,
    key_metadata: KeyMetadata,
    agent: Agent<KMS, KH, C>,
    holder_service: Arc<dyn Holder>,
}

impl<KMS, KH, C> HolderSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    pub fn new(
        state: PresentationHolderState,
        key_metadata: KeyMetadata,
        agent: Agent<KMS, KH, C>,
        holder_service: Arc<dyn Holder>,
    ) -> Self {
        Self {
            state,
            key_metadata,
            agent,
            holder_service,
        }
    }
}

impl<KMS, KH, C> HolderSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    pub async fn handle_message(self, message: HolderMessages) -> Result<Self> {
        debug!("Holder: Updating state");

        let state = match self.state {
            PresentationHolderState::RequestReceived(state) => match message {
                HolderMessages::PreparePresentation => {
                    let thread = state.thread.to_owned();
                    match holder_binder(&state.presentation_request, state.verifier_did.as_deref())
                    {
                        Err(err) => {
                            warn!("Presentation request cannot be answered: {err}");
                            let problem_report = send_problem_report(
                                &self.agent,
                                state.presentation_request.type_.to_owned(),
                                thread.to_owned(),
                                state.connection_id.to_owned(),
                                ProblemReportCode::InvalidPresentationRequest,
                                "presentation request cannot be answered; send a new request",
                            )
                            .await?;
                            PresentationHolderState::Finished(
                                (state, thread, problem_report, Reason::Fail).into(),
                            )
                        }
                        Ok(holder_binder) => {
                            // TODO: check that only one presentation type is requested.
                            let attachment =
                                state.presentation_request.attachments.first().context(
                                    InvalidCredentialRequestSnafu {
                                        details: "attachment not found",
                                    },
                                )?;
                            let proof_request = ProofRequest::try_from(attachment)?;
                            let presentation_input =
                                split_to_inputs_for_pd(&proof_request.input, None)
                                    .context(PresentationDefinitionParseSnafu)?;
                            let presentation_input = presentation_input.first().context(
                                InvalidCredentialRequestSnafu {
                                    details: "presentation definition has no input descriptors",
                                },
                            )?;
                            let vp = self
                                .holder_service
                                .create_presentation_auto(Some(holder_binder), presentation_input)
                                .await
                                .context(CreatePresentationSnafu)?;

                            let presentation = Presentation::create().add_attachment(
                                Attachment::json(serde_json::to_value(vp).unwrap()).finalize(),
                            );

                            let presentation = if let Some(id) = &thread.thid {
                                presentation.set_thread_id(id)
                            } else {
                                presentation
                            };

                            PresentationHolderState::PresentationPrepared(
                                (state, presentation, thread).into(),
                            )
                        }
                    }
                }
                HolderMessages::SetPresentation(presentation) => {
                    let thread = state.thread.to_owned();
                    let presentation = if let Some(id) = &thread.thid {
                        presentation.set_thread_id(id)
                    } else {
                        presentation
                    };
                    PresentationHolderState::PresentationPrepared(
                        (state, presentation, thread).into(),
                    )
                }
                HolderMessages::RejectPresentationRequest(reason) => {
                    let (problem_report, thread) = reject_presentation_request(
                        &self.agent,
                        state.presentation_request.type_.to_owned(),
                        state.thread.to_owned(),
                        state.connection_id.to_owned(),
                        Some(reason),
                    )
                    .await?;
                    PresentationHolderState::Finished(
                        (state, thread, problem_report, Reason::Reject).into(),
                    )
                }

                message_ => {
                    // TODO throw error or change behavior in other way as not changing state leads to not proceeding at all
                    warn!("Holder: Unexpected action to update state {:?}", message_);
                    PresentationHolderState::RequestReceived(state)
                }
            },
            PresentationHolderState::PresentationPrepared(state) => match message {
                HolderMessages::SendPresentation => {
                    let (presentation, thread) = state.send_presentation(&self.agent).await?;
                    PresentationHolderState::Finished((state, thread).into())
                }
                HolderMessages::RejectPresentationRequest(reason) => {
                    let (problem_report, thread) = reject_presentation_request(
                        &self.agent,
                        state.presentation_request.type_.to_owned(),
                        state.thread.to_owned(),
                        state.connection_id.to_owned(),
                        Some(reason),
                    )
                    .await?;
                    PresentationHolderState::Finished(
                        (state, thread, problem_report, Reason::Reject).into(),
                    )
                }
                message_ => {
                    // TODO throw error or change behavior in other way as not changing state leads to not proceeding at all
                    warn!("Holder: Unexpected action to update state {:?}", message_);
                    PresentationHolderState::PresentationPrepared(state)
                }
            },
            PresentationHolderState::Finished(state) => PresentationHolderState::Finished(state),

            _ => InvalidStateSnafu {
                details: format!("Unexpected state: {:#?}", self.state),
            }
            .fail()?,
        };

        Ok(Self {
            state,
            key_metadata: self.key_metadata,
            agent: self.agent,
            holder_service: self.holder_service,
        })
    }

    pub fn state(&self) -> &PresentationHolderState {
        &self.state
    }

    pub fn get_connection_id(&self) -> Option<&String> {
        match &self.state {
            PresentationHolderState::RequestReceived(_)
            | PresentationHolderState::PresentationSent(_)
            | PresentationHolderState::Finished(_) => None,

            PresentationHolderState::PresentationPrepared(state) => Some(&state.connection_id),
        }
    }
}

pub async fn reject_presentation_request<KMS, KH, C>(
    agent: &Agent<KMS, KH, C>,
    type_: MessageType,
    thread: Thread,
    connection_id: String,
    comment: Option<String>,
) -> Result<(ProblemReport, Thread)>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    debug!("Holder: Rejecting presentation request");

    let problem_report = ProblemReport::create()
        .set_message_type(&type_)
        .set_code(ProblemReportCode::PresentationRejected)
        .set_comment(comment.unwrap_or("Presentation request was rejected".to_string()))
        .set_thread(thread.to_owned());

    agent
        .send_message(
            &mut problem_report.to_owned().try_into().context(ParseSnafu)?,
            &connection_id,
        )
        .await
        .context(AgentSnafu)?;

    trace!("HolderSM::reject_presentation_request <<<");
    Ok((problem_report, thread))
}

/// Sends the verifier a problem report.
async fn send_problem_report<KMS, KH, C>(
    agent: &Agent<KMS, KH, C>,
    type_: MessageType,
    thread: Thread,
    connection_id: String,
    code: ProblemReportCode,
    comment: &str,
) -> Result<ProblemReport>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    let problem_report = ProblemReport::create()
        .set_message_type(&type_)
        .set_code(code)
        .set_comment(comment.to_owned())
        .set_thread(thread);

    agent
        .send_message(
            &mut problem_report.to_owned().try_into().context(ParseSnafu)?,
            &connection_id,
        )
        .await
        .context(AgentSnafu)?;

    Ok(problem_report)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use crate::did::universal::UniversalResolver;
    use crate::didcomm::agent::test_utils::test_agent;
    use crate::didcomm::connection::test_utils::create_test_connection;
    use crate::didcomm::protocol::aries::common::message::status::Status;
    use crate::didcomm::protocol::aries::present_proof::Error;
    use crate::didcomm::protocol::aries::present_proof::holder::state_machine::HolderSM;
    use crate::didcomm::protocol::aries::present_proof::holder::states::FinishedState;
    use crate::didcomm::protocol::aries::present_proof::holder::states::{
        PresentationHolderState, RequestReceivedState,
    };
    use crate::didcomm::protocol::aries::present_proof::message::HolderMessages;
    use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
    use crate::didcomm::protocol::aries::present_proof::message::proof_request::{
        ProofOptions, ProofRequest,
    };
    use crate::didcomm::protocol::aries::problem_report::message::{
        ProblemReport, ProblemReportCode,
    };
    use crate::inmem::vault::InMemVault;
    use crate::reqwest::builder::ReqwestClientBuilder;
    use crate::vc::core::{HolderMetadata, HolderService, KeyMetadata};

    #[rstest::rstest]
    #[case::stored_without_verifier_did(None, None)]
    #[case::domain_of_another_verifier(
        Some("did:example:verifier"),
        Some("did:example:another-verifier")
    )]
    #[tokio::test]
    async fn prepare_presentation_reports_a_request_it_cannot_answer(
        #[case] verifier_did: Option<&str>,
        #[case] request_domain: Option<&str>,
    ) {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let definition =
            serde_json::from_value(json!({"id": "pd", "input_descriptors": []})).unwrap();
        let mut proof_request = ProofRequest::new(definition);
        if let Some(domain) = request_domain {
            proof_request = proof_request.set_options(ProofOptions {
                challenge: Some("challenge".to_owned()),
                domain: Some(domain.to_owned()),
            });
        }
        let request = PresentationRequest::new().add_attachment(proof_request.try_into().unwrap());
        let mut state = RequestReceivedState::new(request, connection.id.to_owned())
            .set_thread_id("thread".to_owned());
        state.verifier_did = verifier_did.map(str::to_owned);
        let holder_service = holder_service(&agent);

        let holder_sm = HolderSM::new(
            PresentationHolderState::RequestReceived(state),
            key_metadata(),
            agent,
            Arc::new(holder_service),
        )
        .handle_message(HolderMessages::PreparePresentation)
        .await
        .unwrap();

        let PresentationHolderState::Finished(FinishedState {
            status: Status::Failed(report),
            ..
        }) = holder_sm.state()
        else {
            panic!("request was not finished: {:?}", holder_sm.state());
        };
        assert_eq!(
            report.body.code,
            ProblemReportCode::InvalidPresentationRequest.code()
        );
        let sent: ProblemReport = transport.next_message().await;
        assert_eq!(&sent, report);
    }

    #[tokio::test]
    async fn prepare_presentation_failed_without_input_descriptors() {
        let (agent, _) = test_agent();
        let definition =
            serde_json::from_value(json!({"id": "pd", "input_descriptors": []})).unwrap();
        let request = PresentationRequest::new()
            .add_attachment(ProofRequest::new(definition).try_into().unwrap());
        let state = PresentationHolderState::RequestReceived(
            RequestReceivedState::new(request, "connection".to_owned())
                .set_thread_id("thread".to_owned())
                .set_verifier_did("did:example:verifier".to_owned()),
        );
        let holder_service = HolderService::new(
            agent.kms().to_owned(),
            InMemVault::new(),
            HolderMetadata {
                pop: Default::default(),
                client_id: String::new(),
            },
            UniversalResolver::default(),
            Arc::new(ReqwestClientBuilder::new().build().unwrap()),
        );
        let key_metadata = KeyMetadata {
            kid: "kid".to_owned(),
            did_url: "did:example:holder#key-1".to_owned(),
        };

        let result = HolderSM::new(state, key_metadata, agent, Arc::new(holder_service))
            .handle_message(HolderMessages::PreparePresentation)
            .await;

        assert!(matches!(
            result,
            Err(Error::InvalidCredentialRequest { .. })
        ));
    }
    fn holder_service(
        agent: &crate::didcomm::agent::Agent<
            crate::inmem::kms::LocalKms,
            crate::inmem::kms::KeyHandle,
            crate::didcomm::connection::in_mem::InMemConnectionService,
        >,
    ) -> impl crate::vc::core::Holder + 'static {
        HolderService::new(
            agent.kms().to_owned(),
            InMemVault::new(),
            HolderMetadata {
                pop: Default::default(),
                client_id: String::new(),
            },
            UniversalResolver::default(),
            Arc::new(ReqwestClientBuilder::new().build().unwrap()),
        )
    }

    fn key_metadata() -> KeyMetadata {
        KeyMetadata {
            kid: "kid".to_owned(),
            did_url: "did:example:holder#key-1".to_owned(),
        }
    }
}
