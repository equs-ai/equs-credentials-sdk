use crate::did::universal::UniversalResolver;
use crate::didcomm::agent::Agent;
use crate::didcomm::connection;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::event_emitter::{EventEmitter, EventObservable, Subscription};
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::empty::EMPTY;
use crate::didcomm::protocol::aries::present_proof::holder::state_machine::HolderSM;
use crate::didcomm::protocol::aries::present_proof::holder::states::{
    PresentationHolderState, RequestReceivedState,
};
use crate::didcomm::protocol::aries::present_proof::message::HolderMessages;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::protocol::PresentationProtocol;
use crate::didcomm::protocol::aries::present_proof::{
    AgentSnafu, ConnectionSnafu, InvalidAttachmentSnafu, InvalidStateSnafu, OOBSnafu,
    REQUEST_PRESENTATION, ReqwestClientBuilderSnafu, Result, StorageSnafu,
};
use crate::didcomm::protocol::aries::problem_report::PROBLEM_REPORT;
use crate::didcomm::protocol::outofband::OutOfBandV2Protocol;
use crate::kms::KeyType;
use crate::reqwest::builder::ReqwestClientBuilder;
use crate::storage::Storage;
use crate::vc::core::{Holder as CoreHolder, HolderMetadata, HolderService, KeyMetadata};
use crate::{kms, vault};
use async_trait::async_trait;
use snafu::{IntoError, ResultExt};
use std::sync::Arc;
use tracing::{debug, trace};
use url::Url;

pub mod state_machine;
pub mod states;

#[derive(Clone)]
pub struct PresentationHolder<KMS, KH, S, C, V>
where
    KMS: kms::Kms<KH> + Clone + 'static,
    KH: kms::KeyHandle + 'static,
    S: Storage<String, PresentationHolderState> + Clone + 'static,
    C: ConnectionService + Clone + 'static,
    V: vault::Vault + Clone + 'static,
{
    agent: Agent<KMS, KH, C>,
    key_metadata: KeyMetadata,
    source_id: String,
    storage: S,
    vault: V,
    event_emitter: EventEmitter<String, PresentationHolderState>,
    oob: OutOfBandV2Protocol<KMS, KH, C>,
    connection_key_type: KeyType,

    holder_service: Arc<dyn CoreHolder>,
}

impl<KMS, KH, S, C, V> PresentationHolder<KMS, KH, S, C, V>
where
    KMS: kms::Kms<KH> + Clone + 'static,
    KH: kms::KeyHandle + 'static,
    S: Storage<String, PresentationHolderState> + Clone + 'static,
    C: ConnectionService + Clone + 'static,
    V: vault::Vault + Clone + 'static,
{
    pub async fn new(
        agent: &Agent<KMS, KH, C>,
        key_metadata: KeyMetadata,
        storage: S,
        vault: V,
        invitation: Url,
        connection_key_type: KeyType,
        thread_id: String,
    ) -> Result<Self> {
        debug!("Creating verification Holder state object");

        let oob = OutOfBandV2Protocol::new(agent);

        let invitation = oob
            .parse_invitation(invitation.as_str())
            .context(OOBSnafu)?;
        let presentation_request: PresentationRequest = invitation
            .attachments
            .first()
            .map(|attachment| attachment.to_owned().try_into())
            .transpose()?
            .ok_or_else(|| {
                InvalidAttachmentSnafu {
                    details: "Invitation must contain presentation request attachment",
                }
                .build()
            })?;

        let connection = oob
            .accept_invitation(invitation, connection_key_type.to_owned())
            .await
            .context(OOBSnafu)?;

        let pr_id = presentation_request.id.to_string();

        storage
            .put(
                pr_id.to_owned(),
                PresentationHolderState::RequestReceived(
                    RequestReceivedState::new(presentation_request, connection.id)
                        .set_thread_id(thread_id),
                ),
            )
            .await
            .context(StorageSnafu)?;

        let http_client = ReqwestClientBuilder::new()
            .insecure()
            .build()
            .context(ReqwestClientBuilderSnafu)?;

        let holder_metadata = HolderMetadata {
            pop: Default::default(),
            client_id: "".to_string(),
        };

        let holder_service = HolderService::new(
            agent.kms().to_owned(),
            vault.to_owned(),
            holder_metadata,
            UniversalResolver::default(),
            Arc::new(http_client),
        );

        let holder = Self {
            agent: agent.to_owned(),
            key_metadata,
            source_id: pr_id,
            storage,
            vault,
            event_emitter: EventEmitter::new(),
            oob,
            connection_key_type,
            holder_service: Arc::new(holder_service),
        };

        let presentation_protocol = PresentationProtocol::new_with_holder(holder.to_owned());
        agent
            .register_protocol(presentation_protocol)
            .await
            .context(AgentSnafu)?;
        Ok(holder)
    }
    async fn state_machine(&self) -> Result<HolderSM<KMS, KH, C>> {
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

        Ok(HolderSM::new(
            state,
            self.key_metadata.to_owned(),
            self.agent.to_owned(),
            self.holder_service.to_owned(),
        ))
    }

    pub async fn prepare_presentation(&self) -> Result<()> {
        trace!("Holder::prepare_presentation >>>");
        debug!("Holder {}: Prepare Presentation", self.source_id);

        self.step(HolderMessages::PreparePresentation).await
    }

    pub async fn set_presentation(&self, presentation: Presentation) -> Result<()> {
        trace!("Holder::set_presentation >>>");
        debug!(
            "Holder {}: Set Presentation {:#?}",
            self.source_id, presentation
        );

        self.step(HolderMessages::SetPresentation(presentation))
            .await
    }
    pub async fn send_presentation(&self) -> Result<()> {
        trace!("Holder::send_presentation >>>");
        debug!("Holder {}: Send Presentation", self.source_id);

        self.step(HolderMessages::SendPresentation).await
    }

    pub async fn step(&self, message: HolderMessages) -> Result<()> {
        let holder_sm = self.holder_sm().await?.handle_message(message).await?;

        self.storage
            .put(self.source_id.to_owned(), holder_sm.state().to_owned())
            .await
            .context(StorageSnafu)?;

        self.event_emitter
            .emit(self.source_id.to_owned(), holder_sm.state().to_owned())
            .await;

        Ok(())
    }

    async fn holder_sm(&self) -> Result<HolderSM<KMS, KH, C>> {
        let state = self
            .storage
            .get(&self.source_id.to_owned())
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })?;

        Ok(HolderSM::new(
            state,
            self.key_metadata.to_owned(),
            self.agent.to_owned(),
            self.to_owned().holder_service,
        ))
    }

    async fn establish_connection(&self, their_did: Option<String>) -> Result<()> {
        let sm = self.holder_sm().await?;

        let connection_id = sm.get_connection_id().ok_or_else(|| {
            ConnectionSnafu.into_error(connection::Error::ConnectionNotFound {
                id: self.source_id.to_owned(),
            })
        })?;

        self.oob
            .establish_connection(
                connection_id,
                their_did,
                self.connection_key_type.to_owned(),
            )
            .await
            .context(OOBSnafu)
    }

    pub async fn observe_state(&self) -> (Subscription, EventObservable<PresentationHolderState>) {
        self.event_emitter
            .to_owned()
            .observe(self.source_id.to_owned())
            .await
    }
}

#[async_trait]
impl<KMS, KH, S, C, V> MessageHandler for PresentationHolder<KMS, KH, S, C, V>
where
    KMS: kms::Kms<KH> + Clone + 'static,
    KH: kms::KeyHandle + 'static,
    S: Storage<String, PresentationHolderState> + Clone + 'static,
    C: ConnectionService + Clone + 'static,
    V: vault::Vault + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &[REQUEST_PRESENTATION, PROBLEM_REPORT, EMPTY]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        let their_did = msg.from.to_owned();

        let holder_message = msg.try_into()?;

        let id = match holder_message {
            HolderMessages::PresentationRequestReceived(ref presentation_request) => {
                presentation_request
                    .to_owned()
                    .thread
                    .and_then(|thread| thread.thid)
            }
            ref state => protocol::Snafu {
                details: format!("Invalid Holder Message: {:?}", state),
            }
            .fail()?,
        };

        // TODO: Should return ProblemReport
        let id = id.ok_or_else(|| {
            protocol::Snafu {
                details: "Missing thread ID field in DIDComm message",
            }
            .build()
        })?;

        self.establish_connection(their_did).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        self.step(holder_message).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(())
    }
}
