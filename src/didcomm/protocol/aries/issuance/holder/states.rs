use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::message::credential::Credential;
use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
use crate::didcomm::protocol::aries::problem_report::message::{ProblemReport, Reason};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HolderState {
    OfferReceived(OfferReceivedState),
    RequestSent(RequestSentState),
    Finished(FinishedHolderState),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestSentState {
    pub offer: Option<CredentialOffer>,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OfferReceivedState {
    pub offer: CredentialOffer,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

impl OfferReceivedState {
    pub fn new(offer: CredentialOffer, connection_id: String) -> Self {
        let thid = offer
            .thread
            .as_ref()
            .and_then(|thread| thread.thid.clone())
            .unwrap_or(offer.id.to_string());

        let thread = Thread::new().set_thid(thid);
        trace!("Thread: {:?}", thread);

        OfferReceivedState {
            offer,
            connection_id,
            thread,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinishedHolderState {
    pub offer: Option<CredentialOffer>,
    pub cred_id: Option<String>,
    pub credential: Option<Credential>,
    pub status: Status,
    #[serde(default)]
    pub thread: Thread,
}

impl From<(OfferReceivedState, String, Thread)> for RequestSentState {
    fn from((state, connection_id, thread): (OfferReceivedState, String, Thread)) -> Self {
        trace!("HolderSM: transit state from OfferReceivedState to RequestSentState");
        trace!("Thread: {:?}", state.thread);
        RequestSentState {
            offer: Some(state.offer),
            connection_id,
            thread,
        }
    }
}

impl From<(OfferReceivedState, String, Credential, Thread)> for FinishedHolderState {
    fn from(
        (state, cred_id, credential, thread): (OfferReceivedState, String, Credential, Thread),
    ) -> Self {
        trace!("HolderSM: transit state from OfferReceivedState to FinishedHolderState");
        trace!("Thread: {:?}", thread);
        FinishedHolderState {
            offer: Some(state.offer),
            cred_id: Some(cred_id),
            credential: Some(credential),
            status: Status::Success,
            thread,
        }
    }
}

impl From<(RequestSentState, String, Credential, Thread)> for FinishedHolderState {
    fn from(
        (state, cred_id, credential, thread): (RequestSentState, String, Credential, Thread),
    ) -> Self {
        trace!("HolderSM: transit state from RequestSentState to FinishedHolderState");
        trace!("Thread: {:?}", thread);
        FinishedHolderState {
            offer: state.offer,
            cred_id: Some(cred_id),
            credential: Some(credential),
            status: Status::Success,
            thread,
        }
    }
}

impl From<(RequestSentState, ProblemReport, Thread, Reason)> for FinishedHolderState {
    fn from(
        (state, problem_report, thread, reason): (RequestSentState, ProblemReport, Thread, Reason),
    ) -> Self {
        trace!(
            "HolderSM: transit state from RequestSentState to FinishedHolderState with ProblemReport: {:?}",
            problem_report
        );
        trace!("Thread: {:?}", thread);
        FinishedHolderState {
            offer: state.offer,
            cred_id: None,
            credential: None,
            status: reason.to_status(problem_report),
            thread,
        }
    }
}

impl From<(OfferReceivedState, ProblemReport, Thread, Reason)> for FinishedHolderState {
    fn from(
        (state, problem_report, thread, reason): (
            OfferReceivedState,
            ProblemReport,
            Thread,
            Reason,
        ),
    ) -> Self {
        trace!(
            "HolderSM: transit state from OfferReceivedState to FinishedHolderState with ProblemReport: {:?}",
            problem_report
        );
        trace!("Thread: {:?}", problem_report.thread);
        FinishedHolderState {
            offer: Some(state.offer),
            cred_id: None,
            credential: None,
            status: reason.to_status(problem_report),
            thread,
        }
    }
}
