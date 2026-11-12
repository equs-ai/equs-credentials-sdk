use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::str::FromStr;
use tracing::{debug, trace, warn};

use crate::didcomm::agent::Agent;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::empty::message::Empty;
use crate::didcomm::protocol::aries::issuance::holder::HolderMessages;
use crate::didcomm::protocol::aries::issuance::holder::states::{
    FinishedHolderState, IssuanceHolderState, OfferReceivedState, RequestSentState,
};
use crate::didcomm::protocol::aries::issuance::message::credential::Credential;
use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
use crate::didcomm::protocol::aries::issuance::message::credential_request::CredentialRequest;
use crate::didcomm::protocol::aries::issuance::{
    AgentSnafu, DidUrlResolutionSnafu, InvalidCredentialOfferSnafu, InvalidStateSnafu,
    MessageIsOutOfThreadSnafu, ParseSnafu, Result, VCMetadataSnafu, VaultSnafu,
};
use crate::didcomm::protocol::aries::problem_report::message::{
    ProblemReport, ProblemReportCode, Reason,
};
use crate::kms::{KeyHandle, Kms};
use crate::utils::serde::Helpers;
use crate::vc::claims::Claim;
use crate::vc::core::KeyMetadata;
use crate::vc::formats::json_ld_vc;
use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use crate::{vault, vc};

#[derive(Clone)]
pub struct HolderSM<KMS, KH, C, V>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
    V: vault::Vault + Clone,
{
    state: IssuanceHolderState,
    key_metadata: KeyMetadata,
    agent: Agent<KMS, KH, C>,
    vault: V,
}

impl<KMS, KH, C, V> HolderSM<KMS, KH, C, V>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
    V: vault::Vault + Clone,
{
    pub fn step(
        state: IssuanceHolderState,
        key_metadata: KeyMetadata,
        agent: Agent<KMS, KH, C>,
        vault: V,
    ) -> Self {
        HolderSM {
            state,
            agent,
            key_metadata,
            vault,
        }
    }

    pub fn state(&self) -> &IssuanceHolderState {
        &self.state
    }

    pub async fn handle_message(self, cim: HolderMessages) -> Result<HolderSM<KMS, KH, C, V>> {
        debug!("Holder: Updating state");
        let HolderSM {
            state,
            key_metadata,
            agent,
            vault,
        } = self;
        let state = match state {
            IssuanceHolderState::OfferReceived(state_data) => match cim {
                HolderMessages::CredentialRequestSend => {
                    let did_url = DIDURLBuf::from_str(&key_metadata.did_url)
                        .context(DidUrlResolutionSnafu)?;
                    state_data
                        .send_credential_request(did_url.did(), &agent)
                        .await?
                }
                HolderMessages::CredentialRejectSend(comment) => {
                    state_data.send_credential_reject(comment, &agent).await?
                }
                _ => {
                    warn!(
                        "Credential Issuance can only start on holder side with Credential Offer"
                    );
                    IssuanceHolderState::OfferReceived(state_data)
                }
            },
            IssuanceHolderState::RequestSent(state_data) => match cim {
                HolderMessages::Credential(credential) => {
                    state_data
                        .handle_received_credential(credential, &vault, &agent, &key_metadata)
                        .await?
                }
                HolderMessages::ProblemReport(problem_report) => {
                    let thread = problem_report
                        .thread
                        .clone()
                        .ok_or_else(|| MessageIsOutOfThreadSnafu.build())?;

                    IssuanceHolderState::Finished(
                        (state_data, problem_report.clone(), thread, Reason::Fail).into(),
                    )
                }
                HolderMessages::CredentialRejectSend(comment) => {
                    state_data.send_credential_reject(comment, &agent).await?
                }
                _ => {
                    warn!(
                        "In this state Credential Issuance can accept only Credential and Problem Report"
                    );
                    IssuanceHolderState::RequestSent(state_data)
                }
            },
            IssuanceHolderState::Finished(state_data) => {
                warn!("Exchange is finished, no agent can be sent or received");
                IssuanceHolderState::Finished(state_data)
            }
        };

        trace!("Holder::handle_message <<< state: {:?}", state);
        Ok(HolderSM::step(state, key_metadata, agent, vault))
    }

    pub fn is_terminal_state(&self) -> bool {
        matches!(self.state, IssuanceHolderState::Finished(_))
    }

    pub fn get_credential_offer(&self) -> Result<CredentialOffer> {
        match self.state {
            IssuanceHolderState::OfferReceived(ref state) => Ok(state.offer.clone()),
            IssuanceHolderState::RequestSent(ref state) => state.offer.clone().ok_or(
                InvalidStateSnafu {
                    details: "Invalid  Holder object state: `offer` not found",
                }
                .build(),
            ),
            IssuanceHolderState::Finished(ref state) => state.offer.clone().ok_or(
                InvalidStateSnafu {
                    details: "Invalid Holder object state: `offer` not found",
                }
                .build(),
            ),
        }
    }

    pub fn get_credential(&self) -> Result<(String, Credential)> {
        match self.state {
            IssuanceHolderState::Finished(ref state) => {
                let cred_id = state.cred_id.clone().ok_or(
                    InvalidStateSnafu {
                        details: "Invalid Holder object state: `cred_id` not found",
                    }
                    .build(),
                )?;
                let credential = state.credential.clone().ok_or(
                    InvalidStateSnafu {
                        details: "Invalid Holder object state: `credential` not found",
                    }
                    .build(),
                )?;
                Ok((cred_id, credential))
            }
            _ => Err(InvalidStateSnafu {
                details: format!(
                    "Holder object in state {:?} not ready to get Credential message",
                    self.state
                ),
            }
            .build()),
        }
    }

    pub async fn delete_credential(&self) -> Result<()> {
        trace!("Holder::delete_credential >>>");

        match self.state {
            IssuanceHolderState::Finished(ref state) => {
                let cred_id = state.cred_id.as_deref().ok_or(
                    InvalidStateSnafu {
                        details: "Invalid Holder object state: `cred_id` not found",
                    }
                    .build(),
                )?;
                state.delete_credential(cred_id, &self.vault).await
            }
            _ => Err(InvalidStateSnafu {
                details: format!(
                    "Holder object in state {:?} not ready to delete Credential",
                    self.state,
                ),
            }
            .build()),
        }
    }

    pub fn problem_report(&self) -> Option<&ProblemReport> {
        match self.state {
            IssuanceHolderState::OfferReceived(_) | IssuanceHolderState::RequestSent(_) => None,
            IssuanceHolderState::Finished(ref status) => match &status.status {
                Status::Success | Status::Undefined => None,
                Status::Rejected(problem_report) => problem_report.as_ref(),
                Status::Failed(problem_report) => Some(problem_report),
            },
        }
    }

    pub fn get_connection_id(&self) -> Option<&str> {
        match &self.state {
            IssuanceHolderState::Finished(_) => None,
            IssuanceHolderState::RequestSent(state) => Some(&state.connection_id),
            IssuanceHolderState::OfferReceived(state) => Some(&state.connection_id),
        }
    }
}

impl RequestSentState {
    async fn handle_received_credential<KMS, KH, C>(
        self,
        credential: Credential,
        vault: &impl vault::Vault,
        agent: &Agent<KMS, KH, C>,
        key_metadata: &KeyMetadata,
    ) -> Result<IssuanceHolderState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let thread = credential
            .thread
            .clone()
            .ok_or_else(|| MessageIsOutOfThreadSnafu.build())?;

        match self
            .store_credential(&credential, vault, key_metadata)
            .await
        {
            Ok(cred_id) => {
                if let Some(please_ack) = credential.please_ack.clone() {
                    let ack = Empty::create()
                        .add_ack_ids(please_ack)
                        .set_thread(Thread::from_parent(&thread));

                    agent
                        .send_message(
                            &mut ack.try_into().context(ParseSnafu)?,
                            &self.connection_id,
                        )
                        .await
                        .context(AgentSnafu)?;
                }
                Ok(IssuanceHolderState::Finished(
                    (self, cred_id, credential, thread).into(),
                ))
            }
            Err(err) => {
                warn!("Received credential could not be processed: {err}");
                debug!("Received credential error: {err:?}");

                let problem_report = ProblemReport::create()
                    .set_message_type(&credential.type_)
                    .set_code(ProblemReportCode::InvalidCredential)
                    .set_comment(String::from("credential could not be processed"))
                    .set_thread(thread.clone());

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

    async fn send_credential_reject<KMS, KH, C>(
        self,
        comment: Option<String>,
        agent: &Agent<KMS, KH, C>,
    ) -> Result<IssuanceHolderState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let thread = self.thread.clone();

        let offer = self.offer.as_ref().ok_or(
            InvalidStateSnafu {
                details: "Invalid Holder object state: `offer` not found",
            }
            .build(),
        )?;

        let problem_report = ProblemReport::create()
            .set_message_type(&offer.type_)
            .set_code(ProblemReportCode::CredentialRejected)
            .set_comment(comment.unwrap_or(String::from("credential-offer was rejected")))
            .set_thread(thread.clone());

        agent
            .send_message(
                &mut problem_report.clone().try_into().context(ParseSnafu)?,
                &self.connection_id,
            )
            .await
            .context(AgentSnafu)?;

        Ok(IssuanceHolderState::Finished(
            (self, problem_report, thread, Reason::Reject).into(),
        ))
    }

    async fn store_credential(
        &self,
        credential: &Credential,
        vault: &impl vault::Vault,
        key_metadata: &KeyMetadata,
    ) -> Result<String> {
        trace!("Holder::_store_credential >>>");
        debug!("holder storing received credential");

        let credential_offer = self.offer.as_ref().ok_or(
            InvalidStateSnafu {
                details: "Invalid Holder object state: `offer` not found",
            }
            .build(),
        )?;

        let credential = vc::Credential::LdpVc(credential.get_ldp_vc_credential()?);

        let metadata =
            DefaultMetadataProcessor::resolve_metadata(&credential, key_metadata.clone())
                .context(VCMetadataSnafu)?;

        vault
            .store_credential(credential, &metadata)
            .await
            .context(VaultSnafu)
    }
}

impl OfferReceivedState {
    async fn send_credential_request<KMS, KH, C>(
        self,
        holder_did: &str,
        agent: &Agent<KMS, KH, C>,
    ) -> Result<IssuanceHolderState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        trace!(
            "Holder::OfferReceivedState::send_credential_request >>> offer: {:?}",
            self.offer
        );

        let thread = self.thread.clone();

        match self.make_credential_request(holder_did) {
            Ok(cred_request) => {
                let cred_request = cred_request.set_thread(self.thread.clone());
                let connection_id = self.connection_id.clone();

                agent
                    .send_message(
                        &mut cred_request.try_into().context(ParseSnafu)?,
                        &connection_id,
                    )
                    .await
                    .context(AgentSnafu)?;

                Ok(IssuanceHolderState::RequestSent(
                    (self, connection_id, thread).into(),
                ))
            }
            Err(err) => {
                warn!("Credential offer could not be processed: {err}");
                debug!("Credential offer error: {err:?}");

                let problem_report = ProblemReport::create()
                    .set_message_type(&self.offer.type_)
                    .set_code(ProblemReportCode::InvalidCredentialOffer)
                    .set_comment(String::from("credential offer could not be processed"))
                    .set_thread(thread);

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

    async fn send_credential_reject<KMS, KH, C>(
        self,
        comment: Option<String>,
        agent: &Agent<KMS, KH, C>,
    ) -> Result<IssuanceHolderState>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let thread = self.thread.clone();

        let problem_report = ProblemReport::create()
            .set_message_type(&self.offer.type_)
            .set_code(ProblemReportCode::CredentialRejected)
            .set_comment(comment.unwrap_or(String::from("credential-offer was rejected")))
            .set_thread(thread.clone());

        agent
            .send_message(
                &mut problem_report.clone().try_into().context(ParseSnafu)?,
                &self.connection_id,
            )
            .await
            .context(AgentSnafu)?;

        Ok(IssuanceHolderState::Finished(
            (self, problem_report, thread, Reason::Reject).into(),
        ))
    }

    fn make_credential_request(&self, holder_did: &str) -> Result<CredentialRequest> {
        trace!(
            "Holder::OfferReceivedState::make_credential_request >>> offer: {:?}",
            self.offer
        );
        debug!("holder preparing credential request");
        let mut credential = self.offer.get_ldp_vc_credential()?;

        let cred_subjects = match &mut credential {
            json_ld_vc::Credential::V1(crd) => &mut crd.credential_subjects,
            json_ld_vc::Credential::V2(crd) => &mut crd.credential_subjects,
        };

        let cred_subject = cred_subjects.get_mut(0).ok_or_else(|| {
            InvalidCredentialOfferSnafu {
                details: "Credential subject not found",
            }
            .build()
        })?;

        match cred_subject.get("id") {
            None => cred_subject.put_str("id", holder_did.to_string()),
            Some(Claim::String(id)) if id == holder_did => {}
            Some(_) => {
                return InvalidCredentialOfferSnafu {
                    details: "Credential offer is bound to another subject",
                }
                .fail();
            }
        }

        let cred_req = CredentialRequest::create().set_ldp_vc_credential(&credential);

        trace!("Holder::make_credential_request <<<");
        cred_req
    }
}

impl FinishedHolderState {
    async fn delete_credential(&self, cred_id: &str, vault: &impl vault::Vault) -> Result<()> {
        trace!("Holder::_delete_credential >>> cred_id: {}", cred_id);
        vault.delete_credential(cred_id).await.context(VaultSnafu)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use crate::didcomm::agent::test_utils::test_agent;
    use crate::didcomm::connection::test_utils::create_test_connection;
    use crate::didcomm::protocol::aries::common::message::thread::Thread;
    use crate::didcomm::protocol::aries::issuance::holder::HolderMessages;
    use crate::didcomm::protocol::aries::issuance::holder::holder_fsm::HolderSM;
    use crate::didcomm::protocol::aries::issuance::holder::states::{
        IssuanceHolderState, OfferReceivedState, RequestSentState,
    };
    use crate::didcomm::protocol::aries::issuance::message::credential::Credential;
    use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
    use crate::didcomm::protocol::aries::issuance::message::credential_request::CredentialRequest;
    use crate::didcomm::protocol::aries::problem_report::message::{
        ProblemReport, ProblemReportCode,
    };
    use crate::inmem::vault::InMemVault;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::json_ld_vc;

    const HOLDER_DID: &str = "did:example:holder";

    #[rstest]
    #[case::unbound_offer(None)]
    #[case::offer_bound_to_the_holder(Some(HOLDER_DID))]
    #[tokio::test]
    async fn credential_request_names_the_holder(#[case] offered_subject: Option<&str>) {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let state = offer_received(offered_subject, connection.id);

        HolderSM::step(state, key_metadata(), agent, InMemVault::new())
            .handle_message(HolderMessages::CredentialRequestSend)
            .await
            .unwrap();

        let request: CredentialRequest = transport.next_message().await;
        let vc = serde_json::to_value(request.get_ldp_vc_credential().unwrap()).unwrap();
        assert_eq!(vc["credentialSubject"]["id"], json!(HOLDER_DID));
    }

    #[tokio::test]
    async fn offer_bound_to_another_subject_is_not_requested() {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let state = offer_received(Some("did:example:other"), connection.id);

        let result = HolderSM::step(state, key_metadata(), agent, InMemVault::new())
            .handle_message(HolderMessages::CredentialRequestSend)
            .await;

        assert!(result.is_err());
        let report: ProblemReport = transport.next_message().await;
        assert_eq!(
            report.body.code,
            ProblemReportCode::InvalidCredentialOffer.code()
        );
    }

    #[tokio::test]
    async fn unusable_offer_reported_without_error_details() {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let state = IssuanceHolderState::OfferReceived(OfferReceivedState {
            offer: CredentialOffer::create(),
            connection_id: connection.id,
            thread: thread(),
        });

        let result = HolderSM::step(state, key_metadata(), agent, InMemVault::new())
            .handle_message(HolderMessages::CredentialRequestSend)
            .await;

        assert!(result.is_err());
        let report: ProblemReport = transport.next_message().await;
        assert_eq!(
            report.body.code,
            ProblemReportCode::InvalidCredentialOffer.code()
        );
        assert_eq!(
            report.body.comment.as_deref(),
            Some("credential offer could not be processed")
        );
    }

    #[tokio::test]
    async fn unusable_credential_reported_without_error_details() {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let state = IssuanceHolderState::RequestSent(RequestSentState {
            offer: None,
            connection_id: connection.id,
            thread: thread(),
        });

        let result = HolderSM::step(state, key_metadata(), agent, InMemVault::new())
            .handle_message(HolderMessages::Credential(
                Credential::create().set_thread(thread()),
            ))
            .await;

        assert!(result.is_err());
        let report: ProblemReport = transport.next_message().await;
        assert_eq!(
            report.body.code,
            ProblemReportCode::InvalidCredential.code()
        );
        assert_eq!(
            report.body.comment.as_deref(),
            Some("credential could not be processed")
        );
    }

    fn offer_received(subject: Option<&str>, connection_id: String) -> IssuanceHolderState {
        let mut credential = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2026-01-01T00:00:00Z",
            "credentialSubject": { "givenName": "JANE" }
        });
        if let Some(subject) = subject {
            credential["credentialSubject"]["id"] = json!(subject);
        }
        let credential: json_ld_vc::Credential = serde_json::from_value(credential).unwrap();

        IssuanceHolderState::OfferReceived(OfferReceivedState {
            offer: CredentialOffer::create()
                .set_ldp_vc_credential(&credential)
                .unwrap(),
            connection_id,
            thread: thread(),
        })
    }

    fn thread() -> Thread {
        Thread::new().set_thid("thread".to_owned())
    }

    fn key_metadata() -> KeyMetadata {
        KeyMetadata {
            kid: "kid".to_owned(),
            did_url: format!("{HOLDER_DID}#key-1"),
        }
    }
}
