pub mod holder_fsm;
pub mod states;

use async_trait::async_trait;
use serde_json::json;
use snafu::{IntoError, ResultExt};
use tracing::{debug, trace};
use url::Url;

use crate::didcomm::agent::Agent;
use crate::didcomm::connection;
use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::event_emitter::{EventEmitter, EventObservable, Subscription};
use crate::didcomm::core::message_type::parse_message_type;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::issuance::holder::holder_fsm::HolderSM;
use crate::didcomm::protocol::aries::issuance::holder::states::{HolderState, OfferReceivedState};
use crate::didcomm::protocol::aries::issuance::message::credential::Credential;
use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
use crate::didcomm::protocol::aries::issuance::protocol::IssuanceProtocol;
use crate::didcomm::protocol::aries::issuance::{
    AgentSnafu, ConnectionSnafu, ISSUE_CREDENTIAL, InvalidAttachmentSnafu, InvalidStateSnafu,
    OFFER_CREDENTIAL, OOBSnafu, Result, StorageSnafu,
};
use crate::didcomm::protocol::aries::problem_report::PROBLEM_REPORT;
use crate::didcomm::protocol::aries::problem_report::message::ProblemReport;
use crate::didcomm::protocol::aries::problem_report::protocol::ProblemReportProtocol;
use crate::didcomm::protocol::outofband::OutOfBandV2Protocol;
use crate::kms::KeyType;
use crate::storage::Storage;
use crate::vc::core::KeyMetadata;
use crate::{kms, vault};

#[derive(Debug, Clone)]
pub enum HolderMessages {
    CredentialOffer(CredentialOffer),
    CredentialRequestSend,
    Credential(Credential),
    ProblemReport(ProblemReport),
    CredentialRejectSend(Option<String>),
    Unknown,
}

impl TryFrom<Message> for HolderMessages {
    type Error = protocol::Error;

    fn try_from(value: Message) -> protocol::Result<Self> {
        let (_, _, _, type_) = parse_message_type(&value.type_).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        match type_.as_str() {
            OFFER_CREDENTIAL => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(HolderMessages::CredentialOffer),
            ISSUE_CREDENTIAL => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(HolderMessages::Credential),
            PROBLEM_REPORT => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(HolderMessages::ProblemReport),
            type_ => protocol::Snafu {
                details: format!("Unsupported message type: {type_}"),
            }
            .fail(),
        }
    }
}

#[derive(Clone)]
pub struct Holder<KMS, KH, S, C, V>
where
    KMS: kms::Kms<KH> + Clone + 'static,
    KH: kms::KeyHandle + 'static,
    S: Storage<String, HolderState> + Clone + 'static,
    C: ConnectionService + Clone + 'static,
    V: vault::Vault + Clone + 'static,
{
    agent: Agent<KMS, KH, C>,
    key_metadata: KeyMetadata,
    source_id: String,
    storage: S,
    vault: V,
    event_emitter: EventEmitter<String, HolderState>,
    oob: OutOfBandV2Protocol<KMS, KH, C>,
    connection_key_type: KeyType,
}

impl<KMS, KH, S, C, V> Holder<KMS, KH, S, C, V>
where
    KMS: kms::Kms<KH> + Clone + 'static,
    KH: kms::KeyHandle + 'static,
    S: Storage<String, HolderState> + Clone + 'static,
    C: ConnectionService + Clone + 'static,
    V: vault::Vault + Clone + 'static,
{
    pub async fn new(
        invitation: Url,
        key_metadata: KeyMetadata,
        agent: &Agent<KMS, KH, C>,
        storage: S,
        vault: V,
        connection_key_type: KeyType,
    ) -> Result<Holder<KMS, KH, S, C, V>> {
        debug!("Creating credential Holder state object");

        let oob = OutOfBandV2Protocol::new(agent);

        let invitation = oob
            .parse_invitation(invitation.as_str())
            .context(OOBSnafu)?;

        let offer: CredentialOffer = invitation
            .attachments
            .first()
            .map(|attachment| attachment.clone().try_into())
            .transpose()?
            .ok_or_else(|| {
                InvalidAttachmentSnafu {
                    details: "Invitation must contains credential offer attachment",
                }
                .build()
            })?;

        let connection = oob
            .accept_invitation(invitation, connection_key_type.clone())
            .await
            .context(OOBSnafu)?;

        let offer_id = offer.id.to_string();

        storage
            .put(
                offer_id.to_owned(),
                HolderState::OfferReceived(OfferReceivedState::new(offer, connection.id)),
            )
            .await
            .context(StorageSnafu)?;

        let holder = Holder {
            agent: agent.clone(),
            key_metadata,
            source_id: offer_id,
            storage,
            vault,
            event_emitter: EventEmitter::new(),
            oob: OutOfBandV2Protocol::new(agent),
            connection_key_type,
        };

        let issuance_protocol = IssuanceProtocol::new_with_holder(holder.clone());
        agent
            .register_protocol(issuance_protocol)
            .await
            .context(AgentSnafu)?;

        let problem_report_protocol = ProblemReportProtocol::new(Box::new(holder.clone()));
        agent
            .register_protocol(problem_report_protocol)
            .await
            .context(AgentSnafu)?;

        Ok(holder)
    }

    pub async fn send_request(&mut self) -> Result<()> {
        trace!("Holder::send_request >>>");
        debug!("Holder {}: Sending credential request", self.source_id);
        self.step(HolderMessages::CredentialRequestSend).await
    }

    pub async fn send_reject(
        &mut self,
        connection: ConnectionRecord,
        comment: Option<String>,
    ) -> Result<()> {
        trace!("Holder::send_reject >>> comment: {:?}", comment);
        debug!("Holder {}: Sending credential reject", self.source_id);
        self.step(HolderMessages::CredentialRejectSend(comment))
            .await
    }

    pub async fn get_state(&self) -> Result<HolderState> {
        self.storage
            .get(&self.source_id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })
    }

    pub async fn get_credential_offer(&self) -> Result<CredentialOffer> {
        trace!("Holder::get_credential_offer >>>");
        debug!("Holder {}: Getting credential offer", self.source_id);
        self.holder_sm().await?.get_credential_offer()
    }

    pub async fn get_credential(&self) -> Result<(String, Credential)> {
        trace!("Holder::get_credential >>>");
        debug!("Holder {}: Getting credential", self.source_id);
        self.holder_sm().await?.get_credential()
    }

    pub async fn delete_credential(&self) -> Result<()> {
        debug!("Holder {}: Deleting credential", self.source_id);
        self.holder_sm().await?.delete_credential().await
    }

    pub async fn get_problem_report_message(&self) -> Result<String> {
        trace!("Holder::get_problem_report_message >>>");
        debug!("Holder {}: Getting problem report message", self.source_id);
        let holder_sm = self.holder_sm().await?;

        let problem_report: Option<&ProblemReport> = holder_sm.problem_report();
        Ok(json!(&problem_report).to_string())
    }

    pub async fn step(&self, message: HolderMessages) -> Result<()> {
        // TODO: We need to block this state to avoid race condition
        let holder_sm = self.holder_sm().await?.handle_message(message).await?;

        self.storage
            .put(self.source_id.to_owned(), holder_sm.state().clone())
            .await
            .context(StorageSnafu)?;

        self.event_emitter
            .emit(self.source_id.to_owned(), holder_sm.state().clone())
            .await;

        Ok(())
    }

    pub async fn observe_state(&self) -> (Subscription, EventObservable<HolderState>) {
        self.event_emitter
            .clone()
            .observe(self.source_id.to_owned())
            .await
    }

    async fn holder_sm(&self) -> Result<HolderSM<KMS, KH, C, V>>
    where
        KMS: kms::Kms<KH> + Clone,
        KH: kms::KeyHandle,
        C: ConnectionService + Clone,
        V: vault::Vault + Clone,
    {
        let state = self
            .storage
            .get(&self.source_id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })?;

        Ok(HolderSM::step(
            state,
            self.key_metadata.clone(),
            self.agent.clone(),
            self.vault.clone(),
        ))
    }

    async fn establish_connection(&self, their_did: Option<String>) -> Result<()> {
        let sm = self.holder_sm().await?;

        let connection_id = sm.get_connection_id().ok_or_else(|| {
            ConnectionSnafu.into_error(connection::Error::ConnectionNotFound {
                id: self.source_id.clone(),
            })
        })?;

        self.oob
            .establish_connection(connection_id, their_did, self.connection_key_type.clone())
            .await
            .context(OOBSnafu)
    }
}

#[async_trait]
impl<KMS, KH, S, C, V> MessageHandler for Holder<KMS, KH, S, C, V>
where
    KMS: kms::Kms<KH> + Clone,
    KH: kms::KeyHandle,
    S: Storage<String, HolderState> + Clone,
    C: ConnectionService + Clone,
    V: vault::Vault + Clone,
{
    fn supported_message_types(&self) -> &[&str] {
        &[OFFER_CREDENTIAL, ISSUE_CREDENTIAL, PROBLEM_REPORT]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        let their_did = msg.from.clone();

        let holder_message = msg.try_into()?;

        self.establish_connection(their_did).await.map_err(|err| {
            protocol::Snafu {
                details: format!("{err:?}"),
            }
            .build()
        })?;

        self.step(holder_message).await.map_err(|err| {
            protocol::Snafu {
                details: format!("{err:?}"),
            }
            .build()
        })?;

        Ok(())
    }
}
