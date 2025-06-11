use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::issuer::CredentialInfo;
use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
use crate::didcomm::protocol::aries::issuance::message::credential_request::CredentialRequest;

// Possible Transitions:
// Initial -> OfferSent
// Initial -> Finished
// OfferSent -> CredentialSent
// OfferSent -> Finished
// CredentialSent -> Finished
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IssuerState {
    Initial(InitialState),
    OfferSent(OfferSentState),
    RequestReceived(RequestReceivedState),
    CredentialSent(CredentialSentState),
    Finished(FinishedState),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitialState {
    pub credential_info: CredentialInfo,
    pub offer: CredentialOffer,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OfferSentState {
    pub offer: CredentialOffer,
    pub credential_info: CredentialInfo,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestReceivedState {
    pub offer: CredentialOffer,
    pub credential_info: CredentialInfo,
    pub request: CredentialRequest,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialSentState {
    pub offer: CredentialOffer,
    pub connection_id: String,
    #[serde(default)]
    pub thread: Thread,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinishedState {
    pub offer: CredentialOffer,
    pub cred_id: Option<String>,
    pub status: Status,
    #[serde(default)]
    pub thread: Thread,
}

impl From<(InitialState, String, Thread)> for OfferSentState {
    fn from((state, connection_id, thread): (InitialState, String, Thread)) -> Self {
        trace!("IssuerSM: transit state from InitialState to OfferSentState");
        trace!("Thread: {:?}", thread);
        OfferSentState {
            offer: state.offer,
            credential_info: state.credential_info,
            connection_id,
            thread,
        }
    }
}

impl From<(OfferSentState, CredentialRequest)> for RequestReceivedState {
    fn from((state, request): (OfferSentState, CredentialRequest)) -> Self {
        trace!("IssuerSM: transit state from OfferSentState to RequestReceivedState");
        trace!("Thread: {:?}", state.thread);
        RequestReceivedState {
            offer: state.offer,
            credential_info: state.credential_info,
            request,
            connection_id: state.connection_id,
            thread: state.thread,
        }
    }
}

impl From<RequestReceivedState> for CredentialSentState {
    fn from(state: RequestReceivedState) -> Self {
        trace!("IssuerSM: transit state from RequestReceivedState to CredentialSentState");
        trace!("Thread: {:?}", state.thread);
        CredentialSentState {
            offer: state.offer,
            connection_id: state.connection_id,
            thread: state.thread,
        }
    }
}

impl From<(OfferSentState, Status)> for FinishedState {
    fn from((state, status): (OfferSentState, Status)) -> Self {
        trace!(
            "IssuerSM: transit state from OfferSentState to FinishedState with ProblemReport: {:?}",
            status
        );
        trace!("Thread: {:?}", state.thread);
        FinishedState {
            cred_id: None,
            offer: state.offer,
            status,
            thread: state.thread,
        }
    }
}

impl From<RequestReceivedState> for FinishedState {
    fn from(state: RequestReceivedState) -> Self {
        trace!("IssuerSM: transit state from RequestReceivedState to FinishedState");
        trace!("Thread: {:?}", state.thread);
        FinishedState {
            cred_id: None,
            offer: state.offer,
            status: Status::Success,
            thread: state.thread,
        }
    }
}

impl From<(RequestReceivedState, Status)> for FinishedState {
    fn from((state, status): (RequestReceivedState, Status)) -> Self {
        trace!(
            "IssuerSM: transit state from RequestReceivedState to FinishedState with ProblemReport: {:?}",
            status
        );
        trace!("Thread: {:?}", state.thread);
        FinishedState {
            cred_id: None,
            offer: state.offer,
            status,
            thread: state.thread,
        }
    }
}

impl From<CredentialSentState> for FinishedState {
    fn from(state: CredentialSentState) -> Self {
        trace!("IssuerSM: transit state from CredentialSentState to FinishedState");
        trace!("Thread: {:?}", state.thread);
        FinishedState {
            cred_id: None,
            offer: state.offer,
            status: Status::Success,
            thread: state.thread,
        }
    }
}

impl From<(CredentialSentState, Status)> for FinishedState {
    fn from((state, status): (CredentialSentState, Status)) -> Self {
        trace!(
            "IssuerSM: transit state from CredentialSentState to FinishedState with ProblemReport: {:?}",
            status
        );
        trace!("Thread: {:?}", state.thread);
        FinishedState {
            cred_id: None,
            offer: state.offer,
            status,
            thread: state.thread,
        }
    }
}
