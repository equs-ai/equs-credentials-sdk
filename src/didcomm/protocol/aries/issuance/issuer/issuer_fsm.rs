use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::str::FromStr;
use tracing::{debug, info, warn};

use crate::didcomm::agent::Agent;
use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::issuer::IssuerMessages;
use crate::didcomm::protocol::aries::issuance::issuer::states::{
    InitialState, IssuerState, OfferSentState, RequestReceivedState,
};
use crate::didcomm::protocol::aries::issuance::message::credential::Credential;
use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
use crate::didcomm::protocol::aries::issuance::{
    AgentSnafu, DidUrlResolutionSnafu, KMSSnafu, ParseSnafu, Result,
};
use crate::didcomm::protocol::aries::problem_report::message::{ProblemReport, ProblemReportCode};
use crate::kms::{KeyHandle, Kms};
use crate::vc::formats::json_ld_vc::JsonLdAPI;

#[derive(Clone)]
pub struct IssuerSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    state: IssuerState,
    agent: Agent<KMS, KH, C>,
}

impl<KMS, KH, C> IssuerSM<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    pub fn step(state: IssuerState, agent: Agent<KMS, KH, C>) -> Self {
        IssuerSM { state, agent }
    }

    pub fn state(&self) -> &IssuerState {
        &self.state
    }

    pub async fn handle_message(self, cim: IssuerMessages) -> Result<IssuerSM<KMS, KH, C>> {
        debug!("Issuer::handle_message >>> cim: {:?}", cim);

        let IssuerSM { state, agent } = self;

        let state = match state {
            IssuerState::Initial(state_data) => match cim {
                IssuerMessages::CredentialInit(connection) => {
                    state_data.init_credential(connection, &agent).await?
                }
                _ => {
                    warn!("Credential Issuance can only start on issuer side with init");
                    IssuerState::Initial(state_data)
                }
            },
            IssuerState::OfferSent(state_data) => match cim {
                IssuerMessages::CredentialRequest(request) => {
                    IssuerState::RequestReceived((state_data, request).into())
                }
                IssuerMessages::CredentialProposal(_) => {
                    state_data
                        .handle_received_credential_proposal(&agent)
                        .await?
                }
                IssuerMessages::ProblemReport(problem_report) => IssuerState::Finished(
                    (state_data, Status::Rejected(Some(problem_report))).into(),
                ),
                _ => {
                    warn!(
                        "In this state Credential Issuance can accept only Request, Proposal and Problem Report"
                    );
                    IssuerState::OfferSent(state_data)
                }
            },
            IssuerState::RequestReceived(state_data) => match cim {
                IssuerMessages::CredentialSend => state_data.send_credential(&agent).await?,
                _ => {
                    warn!("In this state Credential Issuance can accept only CredentialSend");
                    IssuerState::RequestReceived(state_data)
                }
            },
            IssuerState::CredentialSent(state_data) => match cim {
                IssuerMessages::ProblemReport(problem_report) => {
                    info!("Interaction closed with failure");
                    IssuerState::Finished(
                        (state_data, Status::Rejected(Some(problem_report))).into(),
                    )
                }
                IssuerMessages::CredentialAck(_ack) => {
                    info!("Interaction closed with success");
                    IssuerState::Finished(state_data.into())
                }
                _ => {
                    warn!(
                        "In this state Credential Issuance can accept only Ack and Problem Report"
                    );
                    IssuerState::CredentialSent(state_data)
                }
            },
            IssuerState::Finished(state_data) => {
                warn!("Exchange is finished, no agent can be sent or received");
                IssuerState::Finished(state_data)
            }
        };

        debug!("Issuer::handle_message <<< state: {:?}", state);
        Ok(IssuerSM::step(state, agent))
    }

    pub fn is_terminal_state(&self) -> bool {
        matches!(self.state, IssuerState::Finished(_))
    }

    pub fn get_credential_offer(&self) -> &CredentialOffer {
        match self.state {
            IssuerState::Initial(ref state) => &state.offer,
            IssuerState::OfferSent(ref state) => &state.offer,
            IssuerState::RequestReceived(ref state) => &state.offer,
            IssuerState::CredentialSent(ref state) => &state.offer,
            IssuerState::Finished(ref state) => &state.offer,
        }
    }

    pub fn problem_report(&self) -> Option<&ProblemReport> {
        match self.state {
            IssuerState::Initial(_)
            | IssuerState::OfferSent(_)
            | IssuerState::RequestReceived(_)
            | IssuerState::CredentialSent(_) => None,
            IssuerState::Finished(ref status) => match &status.status {
                Status::Success | Status::Undefined => None,
                Status::Rejected(problem_report) => problem_report.as_ref(),
                Status::Failed(problem_report) => Some(problem_report),
            },
        }
    }

    pub fn get_connection_id(&self) -> Option<&str> {
        match &self.state {
            IssuerState::Initial(_) | IssuerState::Finished(_) => None,
            IssuerState::OfferSent(state) => Some(&state.connection_id),
            IssuerState::RequestReceived(state) => Some(&state.connection_id),
            IssuerState::CredentialSent(state) => Some(&state.connection_id),
        }
    }
}

impl InitialState {
    async fn init_credential<KMS, KH, C>(
        self,
        connection: ConnectionRecord,
        agent: &Agent<KMS, KH, C>,
    ) -> Result<IssuerState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let mut thread = Thread::new().set_thid(self.offer.id.to_string());

        if let Some(ref their_did) = connection.their_did {
            agent
                .send_message(
                    &mut self.offer.clone().try_into().context(ParseSnafu)?,
                    &connection.id,
                )
                .await
                .context(AgentSnafu)?;
        }

        thread = thread.set_opt_pthid(connection.parent_thread_id.clone());

        Ok(IssuerState::OfferSent((self, connection.id, thread).into()))
    }
}

impl OfferSentState {
    async fn handle_received_credential_proposal<KMS, KH, C>(
        self,
        agent: &Agent<KMS, KH, C>,
    ) -> Result<IssuerState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let problem_report = ProblemReport::create()
            .set_message_type(&self.offer.type_)
            .set_code(ProblemReportCode::Unimplemented)
            .set_comment(String::from("credential-proposal message is not supported"))
            .set_thread(self.thread.clone());

        agent
            .send_message(
                &mut problem_report.clone().try_into().context(ParseSnafu)?,
                &self.connection_id,
            )
            .await
            .context(AgentSnafu)?;

        Ok(IssuerState::Finished(
            (self, Status::Failed(problem_report)).into(),
        ))
    }
}

impl RequestReceivedState {
    async fn send_credential<KMS, KH, C>(self, agent: &Agent<KMS, KH, C>) -> Result<IssuerState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let unsigned_credential = match self.request.get_ldp_vc_credential() {
            Ok(credential) => credential,
            Err(err) => {
                let problem_report = ProblemReport::create()
                    .set_message_type(&self.offer.type_)
                    .set_code(ProblemReportCode::InvalidCredentialRequest)
                    .set_comment(format!("error occurred: {:?}", err))
                    .set_thread(self.thread.clone());

                agent
                    .send_message(
                        &mut problem_report.clone().try_into().context(ParseSnafu)?,
                        &self.connection_id,
                    )
                    .await
                    .context(AgentSnafu)?;

                return Err(err);
            }
        };

        let key_handle = agent
            .kms()
            .get(&self.credential_info.key_metadata.kid)
            .await
            .context(KMSSnafu)?;
        let did_url = DIDURLBuf::from_str(&self.credential_info.key_metadata.did_url)
            .context(DidUrlResolutionSnafu)?;

        let credential = JsonLdAPI::sign_credential(
            unsigned_credential,
            (&did_url, key_handle),
            None,
            agent.did_resolver().clone(),
        )
        .await
        .unwrap();

        let credential_msg = Credential::create()
            .set_ldp_vc_credential(&credential)?
            .add_please_ack_id_to_current_message()
            .set_thread(self.thread.clone());

        agent
            .send_message(
                &mut credential_msg.clone().try_into().context(ParseSnafu)?,
                &self.connection_id,
            )
            .await
            .context(AgentSnafu)?;

        Ok(IssuerState::CredentialSent(self.into()))
    }
}
