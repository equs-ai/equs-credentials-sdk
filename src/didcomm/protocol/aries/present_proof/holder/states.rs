use crate::didcomm::agent::Agent;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::{AgentSnafu, Error, ParseSnafu};
use crate::didcomm::protocol::aries::problem_report::message::{ProblemReport, Reason};
use crate::kms::{KeyHandle, Kms};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use tracing::{debug, trace};

type Result<T> = std::result::Result<T, Error>;

// Possible Transitions:
//
// RequestReceived -> PresentationPrepared, PresentationPreparationFailedState, ProposalSent, Finished
// PresentationPrepared -> PresentationSent, Finished
// PresentationPreparationFailedState -> Finished
// PresentationSent -> Finished
// ProposalPrepared -> ProposalSent
// ProposalSent -> RequestReceived, Finished
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresentationHolderState {
    RequestReceived(RequestReceivedState),
    PresentationPrepared(PresentationPreparedState),
    // ProposalPrepared(ProposalPreparedState),
    PresentationSent(PresentationSentState),
    // ProposalSent(ProposalSentState),
    Finished(FinishedState),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestReceivedState {
    pub presentation_request: PresentationRequest,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

impl RequestReceivedState {
    pub fn new(presentation_request: PresentationRequest, connection_id: String) -> Self {
        Self {
            presentation_request,
            connection_id,
            thread: Default::default(),
        }
    }

    pub fn set_thread_id(mut self, id: String) -> Self {
        self.thread = Thread::new().set_thid(id);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationPreparedState {
    pub presentation_request: PresentationRequest,
    pub presentation: Presentation,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

impl PresentationPreparedState {
    pub async fn send_presentation<KMS, KH, C>(
        &self,
        agent: &Agent<KMS, KH, C>,
    ) -> Result<(Presentation, Thread)>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        debug!("Holder: Sending presentation");
        let thread = self.thread.to_owned();

        let presentation = self.presentation.to_owned();

        agent
            .send_message(
                &mut presentation.to_owned().try_into().context(ParseSnafu)?,
                &self.connection_id,
            )
            .await
            .context(AgentSnafu)?;

        trace!("HolderSM::send_presentation_request <<<");
        Ok((presentation, thread))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSentState {
    pub presentation_request: PresentationRequest,
    pub presentation: Presentation,
    #[serde(default)]
    pub thread: Thread,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinishedState {
    pub presentation_request: Option<PresentationRequest>,
    pub presentation: Option<Presentation>,
    pub status: Status,
    #[serde(default)]
    pub thread: Thread,
}

impl From<(RequestReceivedState, Presentation, Thread)> for PresentationPreparedState {
    fn from((state, presentation, thread): (RequestReceivedState, Presentation, Thread)) -> Self {
        trace!("HolderSM transit state from RequestReceivedState to PresentationPreparedState");
        trace!("Thread: {:?}", thread);
        PresentationPreparedState {
            presentation_request: state.presentation_request,
            presentation,
            connection_id: state.connection_id,
            thread,
        }
    }
}

impl From<(RequestReceivedState, Thread, ProblemReport, Reason)> for FinishedState {
    fn from(
        (state, thread, problem_report, reason): (
            RequestReceivedState,
            Thread,
            ProblemReport,
            Reason,
        ),
    ) -> Self {
        trace!(
            "HolderSM transit state from RequestReceivedState to FinishedState with DeclineProof message"
        );
        trace!("Thread: {:?}", thread);
        FinishedState {
            presentation_request: Some(state.presentation_request),
            presentation: None,
            status: reason.to_status(problem_report),
            thread,
        }
    }
}

impl From<(PresentationPreparedState, Thread)> for FinishedState {
    fn from((state, thread): (PresentationPreparedState, Thread)) -> Self {
        trace!("HolderSM transit state from PresentationPreparedState to FinishedState");
        trace!("Thread: {:?}", thread);
        FinishedState {
            presentation_request: Some(state.presentation_request),
            presentation: Some(state.presentation),
            status: Status::Success,
            thread,
        }
    }
}

impl From<(PresentationPreparedState, Thread, ProblemReport, Reason)> for FinishedState {
    fn from(
        (state, thread, problem_report, reason): (
            PresentationPreparedState,
            Thread,
            ProblemReport,
            Reason,
        ),
    ) -> Self {
        trace!(
            "HolderSM transit state from PresentationPreparedState to FinishedState with DeclineProof message"
        );
        trace!("Thread: {:?}", thread);
        FinishedState {
            presentation_request: Some(state.presentation_request),
            presentation: None,
            status: reason.to_status(problem_report),
            thread,
        }
    }
}
