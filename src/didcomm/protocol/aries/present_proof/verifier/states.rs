use crate::didcomm::agent::Agent;
use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::{
    AgentSnafu, DecodeSnafu, InvalidAttachmentEncodingSnafu, InvalidCredentialRequestSnafu,
    ParseSnafu, Result, VerificationFailedSnafu, holder_binder,
};
use crate::didcomm::protocol::aries::problem_report::message::{ProblemReport, ProblemReportCode};
use crate::kms::{KeyHandle, Kms};
use crate::reqwest::builder::ReqwestClientBuilder;
use crate::vc::core::{Verifier, VerifierService};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use didcomm::AttachmentData;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use tracing::{debug, trace, warn};

// Possible Transitions:
//
// Initial -> PresentationRequestSent
// PresentationRequestSent -> PresentationProposalReceived, Finished
// PresentationProposalReceived -> PresentationRequestSent
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerifierState {
    Initiated(InitialState),
    // PresentationRequestPrepared(PresentationRequestPreparedState),
    PresentationRequestSent(PresentationRequestSentState),
    // PresentationProposalReceived(PresentationProposalReceivedState),
    Finished(FinishedState),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InitialState {
    pub presentation_request: PresentationRequest,
}

impl InitialState {
    pub async fn send_presentation_request<KMS, KH, C>(
        self,
        agent: &Agent<KMS, KH, C>,
        connection: ConnectionRecord,
    ) -> Result<VerifierState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let mut thread = Thread::new().set_thid(self.presentation_request.id.to_string());

        if let Some(ref their_did) = connection.their_did {
            agent
                .send_message(
                    &mut self
                        .presentation_request
                        .to_owned()
                        .try_into()
                        .context(ParseSnafu)?,
                    &connection.id,
                )
                .await
                .context(AgentSnafu)?;
        }

        thread = thread.set_opt_pthid(connection.parent_thread_id.to_owned());

        Ok(VerifierState::PresentationRequestSent(
            (
                self.presentation_request,
                thread,
                connection.id,
                connection.my_did,
            )
                .into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestSentState {
    pub presentation_request: PresentationRequest,
    #[serde(default)]
    pub thread: Thread,
    pub connection_id: String,
    /// DID this verifier sent the request from.
    #[serde(default)]
    pub verifier_did: Option<String>,
}

impl PresentationRequestSentState {
    pub async fn handle_received_presentation<KMS, KH, C>(
        self,
        agent: &Agent<KMS, KH, C>,
        presentation: Presentation,
        verifier_service: &VerifierService,
    ) -> Result<VerifierState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let thread = self.thread.to_owned();
        // .update_received_order(&self.connection.data.did_doc.id);

        // A request stored before binding existed can't be answered, so end the exchange.
        if self.verifier_did.is_none() {
            warn!("Presentation request has no verifier DID and cannot be answered");
            let problem_report = ProblemReport::create()
                .set_message_type(&self.presentation_request.type_)
                .set_code(ProblemReportCode::InvalidPresentationRequest)
                .set_comment(String::from(
                    "presentation request is no longer valid; request a new one",
                ))
                .set_thread(thread.to_owned());

            agent
                .send_message(
                    &mut problem_report.to_owned().try_into().context(ParseSnafu)?,
                    &self.connection_id,
                )
                .await
                .context(AgentSnafu)?;

            return Ok(VerifierState::Finished(
                (
                    self.presentation_request,
                    Status::Failed(problem_report),
                    thread,
                )
                    .into(),
            ));
        }

        match self
            .verify_presentation(&presentation, verifier_service)
            .await
        {
            Ok(_) => Ok(VerifierState::Finished(
                (self.presentation_request, presentation, thread).into(),
            )),
            Err(err) => {
                // thread = thread.increment_sender_order();
                warn!("Presentation verification failed: {err}");
                debug!("Presentation verification error: {err:?}");

                let problem_report = ProblemReport::create()
                    .set_message_type(&self.presentation_request.type_)
                    .set_code(ProblemReportCode::InvalidPresentation)
                    .set_comment(String::from("presentation verification failed"))
                    .set_thread(thread.to_owned());

                agent
                    .send_message(
                        &mut problem_report.try_into().context(ParseSnafu)?,
                        &self.connection_id,
                    )
                    .await
                    .context(AgentSnafu)?;
                Err(err)
            }
        }
    }

    async fn verify_presentation(
        &self,
        presentation: &Presentation,
        verifier_service: &VerifierService,
    ) -> Result<()> {
        trace!(
            "PresentationRequestSentState::verify_presentation >>> presentation: {:?}",
            presentation
        );
        debug!("verifier verifying received presentation");

        let holder_binder =
            holder_binder(&self.presentation_request, self.verifier_did.as_deref())?;

        let attachment = presentation
            .attachments
            .first()
            .ok_or_else(|| {
                InvalidCredentialRequestSnafu {
                    details: "attachment not found",
                }
                .build()
            })?
            .to_owned();

        let presentation = match attachment.data {
            AttachmentData::Json { value } => {
                serde_json::from_value(value.json).context(ParseSnafu)?
            }
            AttachmentData::Base64 { value } => {
                let base64 = BASE64_STANDARD.decode(value.base64).context(DecodeSnafu)?;
                serde_json::from_slice(base64.as_slice()).context(ParseSnafu)?
            }
            AttachmentData::Links { .. } => {
                InvalidAttachmentEncodingSnafu { details: "Links" }.fail()?
            }
        };

        verifier_service
            .verify_presentation(
                Some(holder_binder),
                &presentation,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .context(VerificationFailedSnafu)?;

        trace!("PresentationRequestSentState::verify_presentation <<<");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinishedState {
    pub presentation_request: PresentationRequest,
    pub presentation: Option<Presentation>,
    pub status: Status,
    #[serde(default)]
    pub thread: Thread,
}

impl From<(PresentationRequest, Thread, String, String)> for PresentationRequestSentState {
    fn from(
        (presentation_request, thread, connection_id, verifier_did): (
            PresentationRequest,
            Thread,
            String,
            String,
        ),
    ) -> Self {
        trace!("VerifierSM transit state to PresentationRequestSentState");
        trace!("Thread: {:?}", thread);
        PresentationRequestSentState {
            presentation_request,
            thread,
            connection_id,
            verifier_did: Some(verifier_did),
        }
    }
}

impl From<(PresentationRequest, Presentation, Thread)> for FinishedState {
    fn from(
        (presentation_request, presentation, thread): (PresentationRequest, Presentation, Thread),
    ) -> Self {
        trace!("VerifierSM transit state to FinishedState");
        trace!("Thread: {:?}", thread);
        FinishedState {
            presentation_request,
            presentation: Some(presentation),
            status: Status::Success,
            thread,
        }
    }
}

impl From<(PresentationRequest, Status, Thread)> for FinishedState {
    fn from((presentation_request, status, thread): (PresentationRequest, Status, Thread)) -> Self {
        trace!(
            "VerifierSM transit state to FinishedState with Status: {:?}",
            status
        );
        trace!("Thread: {:?}", thread);
        FinishedState {
            presentation_request,
            presentation: None,
            status,
            thread,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::didcomm::agent::test_utils::test_agent;
    use crate::didcomm::connection::test_utils::create_test_connection;
    use crate::didcomm::protocol::aries::common::message::status::Status;
    use crate::didcomm::protocol::aries::common::message::thread::Thread;
    use crate::didcomm::protocol::aries::present_proof::Error;
    use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
    use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
    use crate::didcomm::protocol::aries::present_proof::verifier::states::{
        FinishedState, PresentationRequestSentState, VerifierState,
    };
    use crate::didcomm::protocol::aries::problem_report::message::{
        ProblemReport, ProblemReportCode,
    };
    use crate::vc::core::VerifierService;

    #[tokio::test]
    async fn presentation_for_a_state_stored_without_verifier_did_ends_the_exchange() {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let state = PresentationRequestSentState {
            presentation_request: PresentationRequest::new(),
            thread: Thread::new().set_thid("thread".to_owned()),
            connection_id: connection.id,
            verifier_did: None,
        };
        let verifier_service =
            VerifierService::new("did:example:verifier", UniversalResolver::default());

        let state = state
            .handle_received_presentation(&agent, Presentation::create(), &verifier_service)
            .await
            .unwrap();

        let VerifierState::Finished(FinishedState {
            status: Status::Failed(report),
            ..
        }) = &state
        else {
            panic!("exchange did not finish: {state:?}");
        };
        assert_eq!(
            report.body.code,
            ProblemReportCode::InvalidPresentationRequest.code()
        );
        let sent: ProblemReport = transport.next_message().await;
        assert_eq!(&sent, report);
    }

    #[tokio::test]
    async fn verify_presentation_failed_for_state_stored_without_verifier_did() {
        let state = VerifierState::PresentationRequestSent(PresentationRequestSentState {
            presentation_request: PresentationRequest::new(),
            thread: Thread::new().set_thid("thread".to_owned()),
            connection_id: "connection".to_owned(),
            verifier_did: Some("did:example:verifier".to_owned()),
        });
        let mut stored = serde_json::to_value(state).unwrap();
        stored["PresentationRequestSent"]
            .as_object_mut()
            .unwrap()
            .remove("verifier_did");
        let VerifierState::PresentationRequestSent(state) = serde_json::from_value(stored).unwrap()
        else {
            panic!("stored state is not PresentationRequestSent");
        };
        let verifier_service =
            VerifierService::new("did:example:verifier", UniversalResolver::default());

        let result = state
            .verify_presentation(&Presentation::create(), &verifier_service)
            .await;

        assert_eq!(state.verifier_did, None);
        assert!(
            matches!(&result, Err(Error::InvalidState { details }) if details.contains("no verifier DID")),
            "unexpected result: {result:?}"
        );
    }
}
