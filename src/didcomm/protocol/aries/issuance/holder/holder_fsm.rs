use snafu::{ResultExt, ensure};
use ssi::dids::{DIDURL, DIDURLBuf};
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
    AgentSnafu, DidUrlResolutionSnafu, InvalidCredentialOfferSnafu, InvalidCredentialSnafu,
    InvalidStateSnafu, MessageIsOutOfThreadSnafu, ParseSnafu, Result, VCMetadataSnafu, VCSnafu,
    VaultSnafu,
};
use crate::didcomm::protocol::aries::problem_report::message::{
    ProblemReport, ProblemReportCode, Reason,
};
use crate::kms::{KeyHandle, Kms};
use crate::utils::serde::Helpers;
use crate::vc::claims::Claim;
use crate::vc::core::KeyMetadata;
use crate::vc::formats::API;
use crate::vc::formats::json_ld_vc;
use crate::vc::formats::json_ld_vc::JsonLdAPI;
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
            .store_credential(&credential, vault, agent, key_metadata)
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

    async fn store_credential<KMS, KH, C>(
        &self,
        credential: &Credential,
        vault: &impl vault::Vault,
        agent: &Agent<KMS, KH, C>,
        key_metadata: &KeyMetadata,
    ) -> Result<String>
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        trace!("Holder::_store_credential >>>");
        debug!("holder storing received credential");

        let credential_offer = self.offer.as_ref().ok_or(
            InvalidStateSnafu {
                details: "Invalid Holder object state: `offer` not found",
            }
            .build(),
        )?;

        let holder_did_url =
            DIDURLBuf::from_str(&key_metadata.did_url).context(DidUrlResolutionSnafu)?;
        let requested = requested_credential(credential_offer, holder_did_url.did())?;
        let credential = credential.get_ldp_vc_credential()?;

        ensure!(
            serde_json::to_value(&credential.claims).context(ParseSnafu)?
                == serde_json::to_value(&requested).context(ParseSnafu)?,
            InvalidCredentialSnafu {
                details: "credential differs from the requested one",
            }
        );

        ensure!(
            signed_by_issuer(&credential),
            InvalidCredentialSnafu {
                details: "credential is not signed by its issuer",
            }
        );

        JsonLdAPI::verify_vc(
            &credential,
            Default::default(),
            agent.did_resolver().clone(),
        )
        .await
        .context(VCSnafu)?;

        let credential = vc::Credential::LdpVc(credential);

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
        let credential = requested_credential(&self.offer, holder_did)?;

        let cred_req = CredentialRequest::create().set_ldp_vc_credential(&credential);

        trace!("Holder::make_credential_request <<<");
        cred_req
    }
}

fn requested_credential(
    offer: &CredentialOffer,
    holder_did: &str,
) -> Result<json_ld_vc::Credential> {
    let mut credential = offer.get_ldp_vc_credential()?;

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

    Ok(credential)
}

fn signed_by_issuer(credential: &json_ld_vc::VC) -> bool {
    let issuer = match &credential.claims {
        json_ld_vc::Credential::V1(crd) => crd.issuer.id(),
        json_ld_vc::Credential::V2(crd) => crd.issuer.id(),
    };

    !credential.proofs.is_empty()
        && credential.proofs.iter().all(|proof| {
            DIDURL::new(proof.verification_method.id().as_str())
                .is_ok_and(|did_url| did_url.did().as_str() == issuer.as_str())
        })
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
    use serde_json::{Value, json};
    use ssi::dids::DIDURLBuf;
    use std::str::FromStr;

    use crate::didcomm::agent::Agent;
    use crate::didcomm::agent::test_utils::test_agent;
    use crate::didcomm::connection::in_mem::InMemConnectionService;
    use crate::didcomm::connection::test_utils::create_test_connection;
    use crate::didcomm::protocol::aries::common::message::status::Status;
    use crate::didcomm::protocol::aries::common::message::thread::Thread;
    use crate::didcomm::protocol::aries::issuance::holder::HolderMessages;
    use crate::didcomm::protocol::aries::issuance::holder::holder_fsm::HolderSM;
    use crate::didcomm::protocol::aries::issuance::holder::states::{
        FinishedHolderState, IssuanceHolderState, OfferReceivedState, RequestSentState,
    };
    use crate::didcomm::protocol::aries::issuance::message::credential::Credential;
    use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
    use crate::didcomm::protocol::aries::issuance::message::credential_request::CredentialRequest;
    use crate::didcomm::protocol::aries::problem_report::message::{
        ProblemReport, ProblemReportCode,
    };
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::vault::InMemVault;
    use crate::kms::{KeyType, Kms};
    use crate::utils::test_utils::create_did_and_key_metadata_by_key_type;
    use crate::vault::Vault;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::json_ld_vc;
    use crate::vc::formats::json_ld_vc::JsonLdAPI;

    const HOLDER_DID: &str = "did:example:holder";

    type TestAgent = Agent<LocalKms, KeyHandle, InMemConnectionService>;

    enum Received {
        Unsigned,
        ProofOverOtherClaims,
        OtherClaims,
        OtherIssuer,
        SignedByAnotherKey,
    }

    #[tokio::test]
    async fn requested_credential_signed_by_its_issuer_is_stored() {
        let (agent, _transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let (issuer_did, issuer_key) = issuer(&agent).await;
        let offer = offer(&issuer_did);
        let credential = sign(&agent, &issuer_key, requested(&offer)).await;
        let vault = InMemVault::new();

        let holder = HolderSM::step(
            request_sent(offer, connection.id),
            key_metadata(),
            agent,
            vault.clone(),
        )
        .handle_message(HolderMessages::Credential(credential_message(&credential)))
        .await
        .unwrap();

        assert!(matches!(
            holder.state(),
            IssuanceHolderState::Finished(FinishedHolderState {
                status: Status::Success,
                ..
            })
        ));
        assert_eq!(vault.get_credentials(None).await.unwrap().len(), 1);
    }

    #[rstest]
    #[case::unsigned(Received::Unsigned)]
    #[case::proof_over_other_claims(Received::ProofOverOtherClaims)]
    #[case::other_claims(Received::OtherClaims)]
    #[case::other_issuer(Received::OtherIssuer)]
    #[case::signed_by_another_key(Received::SignedByAnotherKey)]
    #[tokio::test]
    async fn credential_other_than_the_requested_one_is_not_stored(#[case] received: Received) {
        let (agent, transport) = test_agent();
        let connection = create_test_connection(&agent).await;
        let (issuer_did, issuer_key) = issuer(&agent).await;
        let (other_did, other_key) = issuer(&agent).await;
        let offer = offer(&issuer_did);
        let requested = requested(&offer);
        let mut other_claims = requested.clone();
        other_claims["credentialSubject"]["givenName"] = json!("MALLORY");

        let credential = match received {
            Received::Unsigned => json_ld_vc::VC::new(
                serde_json::from_value(requested).unwrap(),
                Default::default(),
            ),
            Received::ProofOverOtherClaims => json_ld_vc::VC::new(
                serde_json::from_value(requested).unwrap(),
                sign(&agent, &issuer_key, other_claims).await.proofs,
            ),
            Received::OtherClaims => sign(&agent, &issuer_key, other_claims).await,
            Received::OtherIssuer => {
                let mut other_issuer = requested;
                other_issuer["issuer"] = json!(other_did);
                sign(&agent, &other_key, other_issuer).await
            }
            Received::SignedByAnotherKey => sign(&agent, &other_key, requested).await,
        };
        let vault = InMemVault::new();

        let result = HolderSM::step(
            request_sent(offer, connection.id),
            key_metadata(),
            agent,
            vault.clone(),
        )
        .handle_message(HolderMessages::Credential(credential_message(&credential)))
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
        assert!(vault.get_credentials(None).await.unwrap().is_empty());
    }

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

    async fn issuer(agent: &TestAgent) -> (String, KeyMetadata) {
        create_did_and_key_metadata_by_key_type(agent.kms(), KeyType::Ed25519).await
    }

    fn offer(issuer_did: &str) -> CredentialOffer {
        let credential: json_ld_vc::Credential = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1"
            ],
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": issuer_did,
            "issuanceDate": "2026-01-01T00:00:00Z",
            "credentialSubject": {
                "type": ["PermanentResident", "Person"],
                "givenName": "JANE"
            }
        }))
        .unwrap();

        CredentialOffer::create()
            .set_ldp_vc_credential(&credential)
            .unwrap()
    }

    fn requested(offer: &CredentialOffer) -> Value {
        let mut credential = serde_json::to_value(offer.get_ldp_vc_credential().unwrap()).unwrap();
        credential["credentialSubject"]["id"] = json!(HOLDER_DID);
        credential
    }

    async fn sign(agent: &TestAgent, key: &KeyMetadata, credential: Value) -> json_ld_vc::VC {
        JsonLdAPI::sign_credential(
            serde_json::from_value(credential).unwrap(),
            (
                &DIDURLBuf::from_str(&key.did_url).unwrap(),
                agent.kms().get(&key.kid).await.unwrap(),
            ),
            None,
            agent.did_resolver().clone(),
        )
        .await
        .unwrap()
    }

    fn credential_message(credential: &json_ld_vc::VC) -> Credential {
        Credential::create()
            .set_ldp_vc_credential(credential)
            .unwrap()
            .set_thread(thread())
    }

    fn request_sent(offer: CredentialOffer, connection_id: String) -> IssuanceHolderState {
        IssuanceHolderState::RequestSent(RequestSentState {
            offer: Some(offer),
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
