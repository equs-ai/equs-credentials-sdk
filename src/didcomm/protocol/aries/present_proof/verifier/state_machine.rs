use crate::didcomm::agent::Agent;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::present_proof::Result;
use crate::didcomm::protocol::aries::present_proof::message::VerifierMessages;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::verifier::states::VerifierState;
use crate::didcomm::protocol::aries::problem_report::message::ProblemReport;
use crate::kms::{KeyHandle, Kms};
use crate::vc::core::VerifierService;
use tracing::{debug, info, trace, warn};

#[derive(Clone)]
pub struct VerifierSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    state: VerifierState,
    agent: Agent<KMS, KH, C>,

    verifier_service: VerifierService,
}

impl<KMS, KH, C> VerifierSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    pub fn new(
        state: VerifierState,
        agent: Agent<KMS, KH, C>,
        verifier_service: VerifierService,
    ) -> Self {
        VerifierSM {
            agent,
            state,
            verifier_service,
        }
    }
}

impl<KMS, KH, C> VerifierSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    pub async fn handle_message(self, message: VerifierMessages) -> Result<Self> {
        trace!("VerifierSM::step >>> message: {:?}", message);
        debug!("verifier updating state");

        let VerifierSM {
            agent,
            state,
            verifier_service,
        } = self;

        let state = match state {
            VerifierState::Initiated(state) => match message {
                VerifierMessages::SendPresentationRequest(connection_record) => {
                    state
                        .send_presentation_request(&agent, connection_record)
                        .await?
                }
                _ => {
                    // TODO throw error or change behavior in other way as not changing state leads to not proceeding at all
                    warn!("In this state Verifier can only send Presentation Request");
                    VerifierState::Initiated(state)
                }
            },
            VerifierState::PresentationRequestSent(state) => match message {
                VerifierMessages::PresentationReceived(presentation) => {
                    state
                        .handle_received_presentation(&agent, presentation, &verifier_service)
                        .await?
                }
                VerifierMessages::PresentationRejectReceived(problem_report) => {
                    let thread = state.thread.to_owned().set_thid(state.connection_id);
                    VerifierState::Finished(
                        (
                            state.presentation_request,
                            Status::Rejected(Some(problem_report)),
                            thread,
                        )
                            .into(),
                    )
                }
                VerifierMessages::ProblemReport(problem_report) => {
                    info!("Interaction closed with failure");
                    VerifierState::Finished(
                        (
                            state.presentation_request,
                            Status::Rejected(Some(problem_report)),
                            state.thread,
                        )
                            .into(),
                    )
                }
                _ => {
                    // TODO throw error or change behavior in other way as not changing state leads to not proceeding at all
                    warn!("In this state Verifier can accept only Presentation or its Rejection");
                    VerifierState::PresentationRequestSent(state)
                }
            },
            VerifierState::Finished(state) => {
                warn!("Exchange is finished, no agent can be sent or received");
                VerifierState::Finished(state)
            }
        };

        Ok(VerifierSM {
            state,
            agent,
            verifier_service,
        })
    }

    pub fn state(&self) -> &VerifierState {
        &self.state
    }

    pub fn get_presentation_request(&self) -> Result<PresentationRequest> {
        let result = match &self.state {
            VerifierState::Initiated(state) => &state.presentation_request,
            VerifierState::PresentationRequestSent(state) => &state.presentation_request,
            VerifierState::Finished(state) => &state.presentation_request,
        };

        Ok(result.to_owned())
    }

    pub fn problem_report(&self) -> Option<&ProblemReport> {
        match &self.state {
            VerifierState::Initiated(_) | VerifierState::PresentationRequestSent(_) => None,
            VerifierState::Finished(state) => match &state.status {
                Status::Success | Status::Undefined => None,
                Status::Rejected(status) => status.as_ref(),
                Status::Failed(status) => Some(status),
            },
        }
    }

    pub fn get_connection_id(&self) -> Option<&String> {
        match &self.state {
            VerifierState::Initiated(_) | VerifierState::Finished(_) => None,
            VerifierState::PresentationRequestSent(state) => Some(&state.connection_id),
        }
    }
}
