use crate::didcomm::agent::Agent;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_type::MessageType;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::holder::states::PresentationHolderState;
use crate::didcomm::protocol::aries::present_proof::message::HolderMessages;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::{
    AgentSnafu, DecodeSnafu, InvalidAttachmentEncodingSnafu, InvalidCredentialRequestSnafu,
    InvalidStateSnafu, ParseSnafu, PresentationDefinitionParseSnafu,
};
use crate::didcomm::protocol::aries::present_proof::{CreatePresentationSnafu, Result};
use crate::didcomm::protocol::aries::problem_report::message::{
    ProblemReport, ProblemReportCode, Reason,
};
use crate::kms::{KeyHandle, Kms};
use crate::vc::core::{Holder, KeyMetadata};
use crate::vc::presentation_exchange::split_to_inputs_for_pd;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use didcomm::AttachmentData;
use snafu::ResultExt;
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
                    // todo add check that only one type of presentation is requested
                    let attachment =
                        state
                            .presentation_request
                            .attachments
                            .first()
                            .ok_or_else(|| {
                                InvalidCredentialRequestSnafu {
                                    details: "attachment not found",
                                }
                                .build()
                            })?;

                    let pd = match attachment.data.to_owned() {
                        AttachmentData::Json { value } => {
                            serde_json::from_value(value.json).context(ParseSnafu)?
                        }
                        AttachmentData::Base64 { value } => {
                            let base64 =
                                BASE64_STANDARD.decode(value.base64).context(DecodeSnafu)?;
                            serde_json::from_slice(base64.as_slice()).context(ParseSnafu)?
                        }
                        AttachmentData::Links { .. } => {
                            InvalidAttachmentEncodingSnafu { details: "Links" }.fail()?
                        }
                    };
                    let presentation_input = split_to_inputs_for_pd(&pd, None)
                        .context(PresentationDefinitionParseSnafu)?;
                    let vp = self
                        .holder_service
                        .create_presentation_auto(
                            &Default::default(),
                            Default::default(),
                            &presentation_input[0],
                        )
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
