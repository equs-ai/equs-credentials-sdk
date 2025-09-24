use crate::didcomm::agent::Agent;
use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::{
    AgentSnafu, DecodeSnafu, InvalidAttachmentEncodingSnafu, InvalidCredentialRequestSnafu,
    ParseSnafu, Result, VerificationFailedSnafu,
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
use tracing::{debug, trace};

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
            (self.presentation_request, thread, connection.id).into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestSentState {
    pub presentation_request: PresentationRequest,
    #[serde(default)]
    pub thread: Thread,
    pub connection_id: String,
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

        match self
            .verify_presentation(&presentation, verifier_service)
            .await
        {
            Ok(_) => Ok(VerifierState::Finished(
                (self.presentation_request, presentation, thread).into(),
            )),
            Err(err) => {
                // thread = thread.increment_sender_order();

                let problem_report = ProblemReport::create()
                    .set_message_type(&self.presentation_request.type_)
                    .set_code(ProblemReportCode::InvalidPresentation)
                    .set_comment(format!("error occurred: {:?}", err))
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

        let result = verifier_service
            .verify_presentation(
                &Default::default(),
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

impl From<(PresentationRequest, Thread, String)> for PresentationRequestSentState {
    fn from(
        (presentation_request, thread, connection_id): (PresentationRequest, Thread, String),
    ) -> Self {
        trace!("VerifierSM transit state to PresentationRequestSentState");
        trace!("Thread: {:?}", thread);
        PresentationRequestSentState {
            presentation_request,
            thread,
            connection_id,
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
