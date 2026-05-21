use async_trait::async_trait;
use iref::IriRefBuf;
use issuer_fsm::IssuerSM;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{IntoError, ResultExt};
use std::str::FromStr;
use tracing::{debug, trace};
use url::Url;

use crate::did::DIDURLBuf;
use crate::didcomm::agent::Agent;
use crate::didcomm::connection;
use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::event_emitter::{EventEmitter, EventObservable, Subscription};
use crate::didcomm::core::key_mutex::KeyMutex;
use crate::didcomm::core::message_type::parse_message_type;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::empty::EMPTY;
use crate::didcomm::protocol::aries::empty::message::Empty;
use crate::didcomm::protocol::aries::empty::protocol::EmptyProtocol;
use crate::didcomm::protocol::aries::issuance::issuer::states::{InitialState, IssuerState};
use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
use crate::didcomm::protocol::aries::issuance::message::credential_proposal::CredentialProposal;
use crate::didcomm::protocol::aries::issuance::message::credential_request::CredentialRequest;
use crate::didcomm::protocol::aries::issuance::protocol::IssuanceProtocol;
use crate::didcomm::protocol::aries::issuance::{
    AgentSnafu, ConnectionSnafu, DidUrlResolutionSnafu, InvalidAttributesStructureSnafu,
    InvalidStateSnafu, OOBSnafu, PROPOSE_CREDENTIAL, REQUEST_CREDENTIAL, Result, StorageSnafu,
    VCSnafu,
};
use crate::didcomm::protocol::aries::problem_report::PROBLEM_REPORT;
use crate::didcomm::protocol::aries::problem_report::message::ProblemReport;
use crate::didcomm::protocol::aries::problem_report::protocol::ProblemReportProtocol;
use crate::didcomm::protocol::outofband::{InvitationConfig, OutOfBandV2Protocol};
use crate::kms::{KeyHandle, KeyType, Kms};
use crate::storage::Storage;
use crate::vc::claims::Claims;
use crate::vc::core::KeyMetadata;
use crate::vc::formats::json_ld_vc;
use crate::vc::formats::json_ld_vc::{JsonLdAPI, VCMetadata};

#[cfg(test)]
pub mod fixture;
pub mod issuer_fsm;
pub mod states;

#[derive(Debug, Clone)]
pub enum IssuerMessages {
    CredentialInit(ConnectionRecord),
    CredentialRequest(CredentialRequest),
    CredentialSend,
    CredentialProposal(CredentialProposal),
    CredentialAck(Empty),
    ProblemReport(ProblemReport),
    CredentialRejectSend(Option<String>),
    Unknown,
}

impl TryFrom<Message> for IssuerMessages {
    type Error = protocol::Error;

    fn try_from(value: Message) -> protocol::Result<Self> {
        let (_, _, _, type_) = parse_message_type(&value.type_).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        match type_.as_str() {
            PROPOSE_CREDENTIAL => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(IssuerMessages::CredentialProposal),
            REQUEST_CREDENTIAL => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(IssuerMessages::CredentialRequest),
            PROBLEM_REPORT => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(IssuerMessages::ProblemReport),
            EMPTY => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(IssuerMessages::CredentialAck),
            type_ => protocol::Snafu {
                details: format!("Unsupported message type: {type_}"),
            }
            .fail(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialInfo {
    data: json_ld_vc::Credential,
    key_metadata: KeyMetadata,
    name: Option<String>,
}

impl CredentialInfo {
    pub fn new(
        context: Vec<String>,
        types: Vec<String>,
        claims: Claims,
        duration: i64,
        key_metadata: KeyMetadata,
        name: Option<String>,
    ) -> Result<Self> {
        let result = context
            .into_iter()
            .map(|context| IriRefBuf::from_str(&context))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| {
                InvalidAttributesStructureSnafu {
                    details: format!("Invalid context value: {err}"),
                }
                .build()
            })?;

        let iss_did_url = DIDURLBuf::from_string(key_metadata.did_url.to_owned())
            .context(DidUrlResolutionSnafu)?;

        let metadata = VCMetadata::new(result, types, Some(time::Duration::days(duration)))
            .context(VCSnafu)?;

        let data = JsonLdAPI::prepare_credential(
            &metadata,
            &iss_did_url,
            None,
            claims,
            key_metadata.kid.clone(),
        )
        .context(VCSnafu)?
        .unsigned_vc;

        Ok(Self {
            data,
            key_metadata,
            name,
        })
    }
}

#[derive(Clone)]
pub struct Issuer<KMS, KH, C, S>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
    S: Storage<String, IssuerState> + Clone + 'static,
{
    agent: Agent<KMS, KH, C>,
    storage: S,
    event_emitter: EventEmitter<String, IssuerState>,
    oob: OutOfBandV2Protocol<KMS, KH, C>,
    connection_key_type: KeyType,
    key_mutex: KeyMutex,
}

impl<KMS, KH, C, S> Issuer<KMS, KH, C, S>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
    S: Storage<String, IssuerState> + Clone + 'static,
{
    pub async fn new(
        agent: &Agent<KMS, KH, C>,
        storage: S,
        connection_key_type: KeyType,
    ) -> Result<Issuer<KMS, KH, C, S>> {
        debug!("Creating credential Issuer");

        let issuer = Issuer {
            agent: agent.clone(),
            storage,
            event_emitter: EventEmitter::new(),
            oob: OutOfBandV2Protocol::new(agent),
            connection_key_type,
            key_mutex: KeyMutex::new(),
        };

        let issuance_protocol = IssuanceProtocol::new_with_issuer(issuer.clone());
        agent
            .register_protocol(issuance_protocol)
            .await
            .context(AgentSnafu)?;

        let problem_report_protocol = ProblemReportProtocol::new(Box::new(issuer.clone()));
        agent
            .register_protocol(problem_report_protocol)
            .await
            .context(AgentSnafu)?;

        let empty_protocol = EmptyProtocol::new(Box::new(issuer.clone()));
        agent
            .register_protocol(empty_protocol)
            .await
            .context(AgentSnafu)?;

        Ok(issuer)
    }

    pub async fn create_offer(&self, credential_info: CredentialInfo) -> Result<String> {
        let offer = CredentialOffer::create()
            .set_comment(credential_info.name.clone())
            .set_ldp_vc_credential(&credential_info.data)?
            .append_credential_preview(&credential_info.data)?;

        let offer_id = offer.id.to_string();

        self.storage
            .put(
                offer_id.to_string(),
                IssuerState::Initial(InitialState {
                    credential_info,
                    offer,
                }),
            )
            .await
            .context(StorageSnafu)?;

        Ok(offer_id)
    }

    pub async fn create_invitation(
        &self,
        offer_id: &String,
        mut invitation_config: InvitationConfig,
    ) -> Result<Url> {
        let offer = self.get_credential_offer(offer_id).await?;

        invitation_config.attachments.push(offer.try_into()?);

        let (url, connection) = self
            .oob
            .create_invitation(invitation_config)
            .await
            .context(OOBSnafu)?;

        self.step(offer_id, IssuerMessages::CredentialInit(connection))
            .await?;

        Ok(url)
    }

    pub async fn send_credential_offer(
        &self,
        offer_id: &String,
        connection: ConnectionRecord,
    ) -> Result<()> {
        debug!("Issuer: Sending credential offer");
        self.step(offer_id, IssuerMessages::CredentialInit(connection))
            .await
    }

    pub async fn send_credential(&self, id: &String) -> Result<()> {
        debug!("Issuer: Sending credential");
        self.step(id, IssuerMessages::CredentialSend).await
    }

    pub async fn get_state(&self, id: &String) -> Result<IssuerState> {
        self.storage
            .get(id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })
    }

    pub async fn get_credential_offer(&self, id: &String) -> Result<CredentialOffer> {
        let issuer_sm = self.issuer_sm(id).await?;

        Ok(issuer_sm.get_credential_offer().clone())
    }

    pub async fn get_problem_report_message(&self, id: &String) -> Result<String> {
        trace!("Issuer::get_problem_report_message >>>");
        let issuer_sm = self.issuer_sm(id).await?;

        let problem_report: Option<&ProblemReport> = issuer_sm.problem_report();

        Ok(json!(problem_report).to_string())
    }

    pub async fn step(&self, id: &String, message: IssuerMessages) -> Result<()> {
        let guard = self.key_mutex.lock(id).await;

        let issuer_sm = self.issuer_sm(id).await?.handle_message(message).await?;

        self.storage
            .put(id.to_owned(), issuer_sm.state().clone())
            .await
            .context(StorageSnafu)?;

        self.event_emitter
            .emit(id.clone(), issuer_sm.state().clone())
            .await;

        Ok(())
    }

    pub async fn observe_state(&self, id: String) -> (Subscription, EventObservable<IssuerState>) {
        self.event_emitter.clone().observe(id).await
    }

    async fn issuer_sm(&self, id: &String) -> Result<IssuerSM<KMS, KH, C>> {
        let state = self
            .storage
            .get(id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                InvalidStateSnafu {
                    details: "State not found",
                }
                .build()
            })?;

        Ok(IssuerSM::step(state, self.agent.clone()))
    }

    async fn establish_connection(&self, id: &String, their_did: Option<String>) -> Result<()> {
        let sm = self.issuer_sm(id).await?;

        let connection_id = sm.get_connection_id().ok_or_else(|| {
            ConnectionSnafu.into_error(connection::Error::ConnectionNotFound { id: id.to_string() })
        })?;

        self.oob
            .establish_connection(connection_id, their_did, self.connection_key_type.clone())
            .await
            .context(OOBSnafu)
    }
}

#[async_trait]
impl<KMS, KH, C, S> MessageHandler for Issuer<KMS, KH, C, S>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
    S: Storage<String, IssuerState> + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &[
            PROPOSE_CREDENTIAL,
            REQUEST_CREDENTIAL,
            PROBLEM_REPORT,
            EMPTY,
        ]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        let their_did = msg.from.clone();

        let issuer_message = msg.try_into()?;

        let id = match issuer_message {
            IssuerMessages::CredentialRequest(ref request) => {
                request.thread.clone().and_then(|thread| thread.thid)
            }
            IssuerMessages::CredentialProposal(ref proposal) => {
                proposal.thread.clone().and_then(|thread| thread.thid)
            }
            IssuerMessages::CredentialAck(ref ack) => {
                ack.thread.clone().and_then(|thread| thread.pthid)
            }
            IssuerMessages::ProblemReport(ref report) => {
                report.thread.clone().and_then(|thread| thread.pthid)
            }
            ref state => protocol::Snafu {
                details: format!("Invalid Issuer Message: {:?}", state),
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

        self.establish_connection(&id, their_did)
            .await
            .map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        self.step(&id, issuer_message).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use crate::didcomm::agent::test_utils::test_agent;
    use crate::didcomm::connection::test_utils::create_test_connection;
    use crate::didcomm::connection::{ConnectionService, ConnectionState};
    use crate::didcomm::core::message_id::MessageId;
    use crate::didcomm::protocol::aries::common::message::thread::Thread;
    use crate::didcomm::protocol::aries::issuance::issuer::Issuer;
    use crate::didcomm::protocol::aries::issuance::issuer::fixture::credential_info;
    use crate::didcomm::protocol::aries::issuance::issuer::states::{
        InitialState, IssuerState, OfferSentState,
    };
    use crate::didcomm::protocol::aries::issuance::message::credential_offer::CredentialOffer;
    use crate::didcomm::protocol::outofband::InvitationConfig;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::storage::InMemStorage;
    use crate::kms::KeyType;
    use crate::storage::Storage;

    #[tokio::test]
    async fn create_offer_success() {
        let (agent, _) = test_agent();
        let expected_state = initial_state(agent.kms()).await;

        let issuer = Issuer::new(
            &agent,
            InMemStorage::<String, IssuerState>::new(),
            KeyType::P256,
        )
        .await
        .unwrap();

        let offer_id = issuer
            .create_offer(expected_state.credential_info.clone())
            .await
            .unwrap();

        let state = issuer.get_state(&offer_id).await.unwrap();
        assert!(matches!(state, IssuerState::Initial(expected_state)));

        let offer = issuer.get_credential_offer(&offer_id).await.unwrap();
        assert_eq!(offer, expected_state.offer);
    }

    #[tokio::test]
    async fn create_invitation_success() {
        let (agent, _) = test_agent();
        let initial_state = initial_state(agent.kms()).await;
        let offer_id = MessageId::test_id().to_string();
        let expected_state = offer_sent_state(initial_state.clone()).await;

        let storage = InMemStorage::<String, IssuerState>::new();
        storage
            .put(offer_id.to_owned(), IssuerState::Initial(initial_state))
            .await
            .unwrap();

        let issuer = Issuer::new(&agent, storage, KeyType::P256).await.unwrap();

        let invitation_config = InvitationConfig {
            key_type: KeyType::P256,
            label: "Issuer's Invitation".to_string(),
            goal: "Credential Offer".to_string(),
            goal_code: "offer-credential".to_string(),
            attachments: vec![],
        };

        let invitation = issuer
            .create_invitation(&offer_id, invitation_config)
            .await
            .unwrap();

        let state = issuer.get_state(&offer_id).await.unwrap();
        assert!(matches!(state, IssuerState::OfferSent(expected_state)));

        let invitation = issuer.oob.parse_invitation(invitation.as_str()).unwrap();

        let offer: CredentialOffer = invitation
            .attachments
            .first()
            .map(|attachment| attachment.clone().try_into())
            .unwrap()
            .unwrap();

        let expected_offer = expected_state.offer.set_thread(Thread::default());
        assert_eq!(offer, expected_offer);
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid state: State not found")]
    async fn create_invitation_fails_without_offer() {
        let (agent, _) = test_agent();

        let issuer = Issuer::new(
            &agent,
            InMemStorage::<String, IssuerState>::new(),
            KeyType::P256,
        )
        .await
        .unwrap();

        let invitation_config = InvitationConfig {
            key_type: KeyType::P256,
            label: "Issuer's Invitation".to_string(),
            goal: "Credential Offer".to_string(),
            goal_code: "offer-credential".to_string(),
            attachments: vec![],
        };

        issuer
            .create_invitation(&"fake_id".to_string(), invitation_config)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn send_offer_success() {
        let (agent, transport) = test_agent();
        let initial_state = initial_state(agent.kms()).await;
        let offer_id = MessageId::test_id().to_string();
        let expected_state = offer_sent_state(initial_state.clone()).await;

        let storage = InMemStorage::<String, IssuerState>::new();
        storage
            .put(offer_id.to_owned(), IssuerState::Initial(initial_state))
            .await
            .unwrap();

        let issuer = Issuer::new(&agent, storage, KeyType::P256).await.unwrap();

        let connection = create_test_connection(&agent).await;

        issuer
            .send_credential_offer(&offer_id, connection)
            .await
            .unwrap();

        let state = issuer.get_state(&offer_id).await.unwrap();
        assert!(matches!(state, IssuerState::OfferSent(expected_state)));

        let offer: CredentialOffer = transport.next_message().await;
        let expected_offer = expected_state.offer.set_thread(Thread::default());
        assert_eq!(offer, expected_offer);
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid state: State not found")]
    async fn send_offer_fails_when_incorrect_offer_id() {
        let (agent, transport) = test_agent();
        let initial_state = initial_state(agent.kms()).await;
        let offer_id = MessageId::test_id().to_string();
        let expected_state = offer_sent_state(initial_state.clone()).await;

        let storage = InMemStorage::<String, IssuerState>::new();
        storage
            .put(offer_id.to_owned(), IssuerState::Initial(initial_state))
            .await
            .unwrap();

        let issuer = Issuer::new(&agent, storage, KeyType::P256).await.unwrap();

        let connection = create_test_connection(&agent).await;

        issuer
            .send_credential_offer(&"fake_id".to_string(), connection)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn send_offer_fails_when_connection_incomplete() {
        let (agent, transport) = test_agent();
        let initial_state = initial_state(agent.kms()).await;
        let offer_id = MessageId::test_id().to_string();
        let expected_state = offer_sent_state(initial_state.clone()).await;

        let storage = InMemStorage::<String, IssuerState>::new();
        storage
            .put(offer_id.to_owned(), IssuerState::Initial(initial_state))
            .await
            .unwrap();

        let issuer = Issuer::new(&agent, storage, KeyType::P256).await.unwrap();

        let mut connection = create_test_connection(&agent).await;
        connection.their_did = None;
        connection.state = ConnectionState::Initial;
        agent
            .connection_service()
            .update_connection(connection.clone())
            .await
            .unwrap();

        issuer
            .send_credential_offer(&offer_id.to_string(), connection)
            .await
            .unwrap();
    }

    async fn initial_state(kms: &LocalKms) -> InitialState {
        let credential_info = credential_info(kms).await;
        let offer = CredentialOffer::create()
            .set_comment(credential_info.name.clone())
            .append_credential_preview(&credential_info.data)
            .unwrap()
            .set_ldp_vc_credential(&credential_info.data)
            .unwrap();

        InitialState {
            credential_info: credential_info.clone(),
            offer,
        }
    }

    async fn offer_sent_state(initial_state: InitialState) -> OfferSentState {
        OfferSentState {
            offer: initial_state.offer,
            credential_info: initial_state.credential_info,
            connection_id: MessageId::test_id().to_string(),
            thread: Thread::new().set_thid(MessageId::test_id().to_string()),
        }
    }
}
