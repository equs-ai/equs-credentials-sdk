use std::marker::PhantomData;

use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{Location, ResultExt, Snafu};
use ssi::dids::document::Represented;
use url::Url;

use crate::did::didpeer::{DIDPeer, DidPeerService};
use crate::did::{DID, DIDResolver, VerificationMethodKey, VerificationRelationshipType};
use crate::didcomm::agent::Agent;
use crate::didcomm::connection::{
    ConnectionRecord, ConnectionRole, ConnectionService, ConnectionState, CreateOptions,
};
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::service::DIDCOMM_SCHEME;
use crate::didcomm::{agent, connection, service};
use crate::kms::{KeyHandle, KeyType, Kms};
use crate::{did, kms};

const PROTOCOL_NAME: &str = "out-of-band";
const PROTOCOL_VERSION: &str = "2.0";
const INVITATION_TYPE: &str = "https://didcomm.org/out-of-band/2.0/invitation";

pub const INVITATION_CREATED_EVENT: &str = "oob-invitation-created";
pub const INVITATION_ACCEPTED_EVENT: &str = "oob-invitation-accepted";
pub const INVITATION_RECEIVED_EVENT: &str = "oob-invitation-received";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Connection error"))]
    Connection {
        source: connection::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Invalid invitation URL: {details}"))]
    InvalidInvitationUrl { details: String },
    #[snafu(display("Message parsing error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("KMS service error"))]
    KMS {
        source: kms::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Did generation service error"))]
    DID {
        source: did::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DIDComm service error"))]
    DIDComm {
        source: service::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Agent error"))]
    Agent {
        source: agent::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

// OOB v2 Invitation as per the spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub from: String,
    pub body: InvitationBody,
    pub attachments: Vec<didcomm::Attachment>,
}
/// Configuration for creating invitations
#[derive(Debug, Clone)]
pub struct InvitationConfig {
    pub key_type: KeyType,
    pub label: String,
    pub goal: String,
    pub goal_code: String,
    pub attachments: Vec<didcomm::Attachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationBody {
    pub goal_code: String,
    pub goal: Option<String>,
    pub accept: Option<Vec<String>>,
}

/// OutOfBandV2Protocol implements the Out-of-Band protocol v2
#[derive(Clone)]
pub struct OutOfBandV2Protocol<KMS, KH, C>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
{
    agent: Agent<KMS, KH, C>,
    endpoint: Url,
    pub event_emitter: EventEmitter<&'static str, Event>,
    _phantom: PhantomData<KH>,
}

impl<KMS, KH, C> OutOfBandV2Protocol<KMS, KH, C>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
{
    pub fn new(agent: &Agent<KMS, KH, C>) -> Self {
        Self {
            agent: agent.clone(),
            endpoint: agent.configuration().endpoint.to_owned(),
            event_emitter: EventEmitter::<&'static str, Event>::new(),
            _phantom: PhantomData,
        }
    }

    /// Create an out-of-band invitation
    pub async fn create_invitation(
        &self,
        config: InvitationConfig,
    ) -> Result<(Url, ConnectionRecord)> {
        let my_did = self.create_did(config.key_type.clone()).await?;
        let invite = Invitation {
            id: MessageId::new().to_string(),
            type_: INVITATION_TYPE.to_string(),
            from: my_did.clone(),
            body: InvitationBody {
                goal_code: config.goal_code,
                goal: Some(config.goal),
                accept: Some(vec!["didcomm/v2".to_string()]),
            },
            attachments: config.attachments,
        };

        // Create a connection and invitation using the connection service
        let connection = self
            .agent
            .connection_service()
            .create_connection(
                &my_did,
                CreateOptions {
                    label: Some(config.label),
                    auto_accept: None,
                    alias: None,
                    role: ConnectionRole::Inviter,
                    state: ConnectionState::Invited,
                    pthid: invite.id.to_owned(),
                    metadata: Default::default(),
                },
            )
            .await
            .context(ConnectionSnafu)?;

        let invite_json = serde_json::to_string(&invite).context(ParseSnafu)?;
        let encoded_invite = crate::utils::b64::encode(invite_json.as_bytes());

        let mut invitation_url = self.endpoint.to_owned();
        invitation_url.set_query(Some(&format!("_oob={encoded_invite}")));

        // Emit an event for the invitation creation
        self.event_emitter
            .emit(
                INVITATION_CREATED_EVENT,
                Event::InvitationCreated {
                    connection_id: connection.id.clone(),
                    invitation_url: invitation_url.to_string(),
                },
            )
            .await;

        Ok((invitation_url, connection))
    }

    async fn create_did(&self, key_type: KeyType) -> Result<DID> {
        let (_, kh) = self
            .agent
            .kms()
            .create_and_handle(key_type, Default::default())
            .await
            .context(KMSSnafu)?;

        // TODO: Fix issue while trying construct with DIDPeerService struct
        let service: DidPeerService = serde_json::from_value(json! ({
            "id": "#didcomm-1",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": self.endpoint.to_string(),
                "accept": [
                    "didcomm/v2",
                    "didcomm/aip2;env=rfc587"
                ],
                "routingKeys": ["#key-0"]
            }
        }))
        .unwrap();

        let my_did = DIDPeer::generate_did_peer4(
            &[VerificationMethodKey {
                key: &kh,
                verification_relationships: vec![
                    VerificationRelationshipType::Authentication,
                    VerificationRelationshipType::Assertion,
                    VerificationRelationshipType::KeyAgreement,
                ]
                .into_iter()
                .collect(),
            }],
            &vec![service],
        )
        .context(DIDSnafu)?;
        Ok(my_did)
    }

    /// Accept an out-of-band invitation from a parsed Invitation struct
    pub async fn accept_invitation(
        &self,
        invitation: Invitation,
        key_type: KeyType, //TODO: Should be replaced with new AcceptConfig struct
    ) -> Result<ConnectionRecord> {
        let their_did = ssi::dids::DID::new(invitation.from.as_bytes()).unwrap();
        let resolution = self
            .agent
            .did_resolver()
            .resolve_representation(their_did, Default::default())
            .await
            .unwrap()
            .document;
        let their_did_doc: Represented = serde_json::from_slice(&resolution).unwrap();

        let my_did = self.create_did(key_type.clone()).await?;
        let mut connection = self
            .agent
            .connection_service()
            .create_connection(
                &my_did,
                CreateOptions {
                    label: invitation.body.goal.clone(),
                    role: ConnectionRole::Invitee,
                    state: ConnectionState::Accepted,
                    alias: None,
                    auto_accept: Some(true),
                    metadata: Default::default(),
                    pthid: invitation.id.to_owned(),
                },
            )
            .await
            .context(ConnectionSnafu)?;

        connection.thread_id = Some(invitation.id.clone());
        connection.their_did = Some(their_did_doc.document().id.to_string());
        connection.label = Some(invitation.body.goal_code);
        connection.alias = invitation.body.goal;

        self.agent
            .connection_service()
            .update_connection(connection.clone())
            .await
            .context(ConnectionSnafu)?;

        Ok(connection)
    }

    pub async fn establish_connection(
        &self,
        connection_id: &str,
        their_did: Option<String>,
        key_type: KeyType,
    ) -> Result<()> {
        let mut connection = self
            .agent
            .connection_service()
            .get_connection(connection_id)
            .await
            .context(ConnectionSnafu)?;

        match connection.state {
            ConnectionState::Invited => {
                let new_did = self.create_did(key_type).await?;
                connection.my_did = new_did;
                connection.their_did = their_did;
                connection.state = ConnectionState::Completed;
            }
            ConnectionState::Accepted => {
                connection.their_did = their_did;
                connection.state = ConnectionState::Completed;
            }
            _ => return Ok(()),
        }

        self.agent
            .connection_service()
            .update_connection(connection)
            .await
            .context(ConnectionSnafu)
    }

    /// Parse an invitation from a URL or JSON string
    pub fn parse_invitation(&self, invitation_str: &str) -> Result<Invitation> {
        if invitation_str.starts_with("http") || invitation_str.starts_with(DIDCOMM_SCHEME) {
            let url = Url::parse(invitation_str).map_err(|_| Error::InvalidInvitationUrl {
                details: "Invalid URL format".to_string(),
            })?;

            let oob_param = url
                .query_pairs()
                .find(|(key, _)| key == "oob" || key == "_oob")
                .ok_or_else(|| Error::InvalidInvitationUrl {
                    details: "Missing 'oob' parameter in URL".to_string(),
                })?
                .1
                .to_string();

            let decoded =
                crate::utils::b64::decode(&oob_param).map_err(|_| Error::InvalidInvitationUrl {
                    details: "Invalid base64 encoding".to_string(),
                })?;

            let invitation: Invitation = serde_json::from_slice(&decoded).context(ParseSnafu)?;
            if invitation.type_ != INVITATION_TYPE {
                return Err(Error::InvalidInvitationUrl {
                    details: format!("Invalid invitation type: {}", invitation.type_),
                });
            }

            Ok(invitation)
        } else {
            let invitation: Invitation =
                serde_json::from_str(invitation_str).context(ParseSnafu)?;

            if invitation.type_ != INVITATION_TYPE {
                return Err(Error::InvalidInvitationUrl {
                    details: format!("Invalid invitation type: {}", invitation.type_),
                });
            }

            Ok(invitation)
        }
    }
}

#[async_trait]
impl<KMS, KH, C> Protocol for OutOfBandV2Protocol<KMS, KH, C>
where
    KMS: Kms<KH> + Clone + 'static,
    KH: KeyHandle,
    C: ConnectionService + Clone + 'static,
{
    fn protocol_name(&self) -> &'static str {
        PROTOCOL_NAME
    }

    fn protocol_version(&self) -> &'static str {
        PROTOCOL_VERSION
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        vec![]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    InvitationReceived {
        invitation: Invitation,
    },
    InvitationCreated {
        connection_id: String,
        invitation_url: String,
    },
    InvitationAccepted {
        connection_id: String,
        invitation_url: String,
    },
}
