use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};
use time::OffsetDateTime;
use tracing::{debug, info};
use uuid::Uuid;

use crate::did::DID;
use crate::didcomm;
use crate::didcomm::agent;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::envelope::{Attachment, Message};
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::service::DIDCommService;
use crate::kms::{KeyHandle, Kms};
use crate::storage;
use crate::storage::Storage;

// Protocol constants
const PROTOCOL_NAME: &str = "basicmessage";
const PROTOCOL_VERSION: &str = "2.0";
const MESSAGE_TYPE: &str = "message";

pub const MESSAGE_RECEIVED_EVENT: &str = "basic-message-received";
pub const MESSAGE_SENT_EVENT: &str = "basic-message-sent";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Message parsing error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Storage error"))]
    Storage {
        source: storage::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DIDComm service error"))]
    DIDComm {
        source: didcomm::service::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Agent error"))]
    Agent {
        source: agent::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Message sender service error"))]
    MessageSender {
        source: didcomm::core::message_sender::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

// Basic message structure as per the spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicMessageContent {
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Sender { my_did: DID, their_did: DID },
    Receiver { my_did: DID, their_did: DID },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicMessageRecord {
    pub id: String,
    pub role: Role,
    pub thread_id: Option<String>,
    pub parent_thread_id: Option<String>,
    pub timestamp: Option<i64>,
    pub content: BasicMessageContent,
}

// Events emitted by this protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    MessageReceived {
        message_id: String,
        thread_id: Option<String>,
        parent_thread_id: Option<String>,
        connection_id: String,
        content: String,
        created_time: Option<u64>,
    },
    MessageSent {
        message_id: String,
        to_did: String,
        content: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendOptions {
    pub(crate) thread_id: Option<String>,
    pub(crate) parent_thread_id: Option<String>,
}

// BasicMessageProtocol implements the Basic Message protocol v2
#[derive(Clone)]
pub struct BasicMessageProtocol<S>
where
    S: Storage<String, BasicMessageRecord> + Clone + 'static,
{
    service: DIDCommService,
    storage: S,
    pub event_emitter: EventEmitter<&'static str, Event>,
}

impl<S> BasicMessageProtocol<S>
where
    S: Storage<String, BasicMessageRecord> + Clone + 'static,
{
    /// Create a new Basic Message Protocol instance
    pub async fn new<KMS, KH, C>(agent: &agent::Agent<KMS, KH, C>, storage: S) -> Self
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
        S: Storage<String, BasicMessageRecord> + Clone + 'static,
    {
        Self {
            service: agent.didcomm_service().clone(),
            storage,
            event_emitter: EventEmitter::<&'static str, Event>::new(),
        }
    }

    pub fn creat_message_as_attachment(&self, content: &str) -> Result<Attachment> {
        let basic_msg = BasicMessageContent {
            content: content.to_string(),
        };
        let message = Message::build(
            Uuid::new_v4().to_string(),
            MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: MESSAGE_TYPE.to_string(),
            }
            .to_string(),
            serde_json::to_value(basic_msg).context(ParseSnafu)?,
        )
        .finalize();

        let message_json = serde_json::to_value(&message).context(ParseSnafu)?;

        Ok(Attachment::json(message_json).finalize())
    }

    pub async fn send_message(
        &self,
        my_did: DID,    //TODO: Extend sending by Connection id
        their_did: DID, //TODO: Extend sending by Connection id
        content: String,
        options: SendOptions,
    ) -> Result<String> {
        info!("Sending basic message to {}: {}", their_did, content);
        let message_id = Uuid::new_v4().to_string();
        let utc_now = OffsetDateTime::now_utc().unix_timestamp();
        let message_content = BasicMessageContent {
            content: content.clone(),
        };

        // Create the DIDComm message
        let mut msg_builder = Message::build(
            message_id.clone(),
            MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: MESSAGE_TYPE.to_string(),
            }
            .to_string(),
            serde_json::to_value(message_content).context(ParseSnafu)?,
        );
        msg_builder = msg_builder.from(my_did.clone());

        if let Some(pthid) = &options.parent_thread_id {
            msg_builder = msg_builder.pthid(pthid.clone())
        };
        if let Some(thid) = &options.thread_id {
            msg_builder = msg_builder.pthid(thid.clone())
        };
        let message = msg_builder.finalize();

        // Send the message
        self.service
            .send_message(&message, their_did.clone(), &Default::default())
            .await
            .context(DIDCommSnafu)?;

        let record = BasicMessageRecord {
            id: message_id.clone(),
            role: Role::Sender {
                my_did,
                their_did: their_did.clone(),
            },
            thread_id: options.thread_id,
            parent_thread_id: options.parent_thread_id,
            timestamp: Some(OffsetDateTime::now_utc().unix_timestamp()),
            content: BasicMessageContent {
                content: content.clone(),
            },
        };
        self.storage
            .put(message_id.clone(), record)
            .await
            .context(StorageSnafu)?;
        let event = Event::MessageSent {
            message_id: message_id.clone(),
            to_did: their_did,
            content,
        };

        // Emit message sent event
        self.event_emitter.emit(MESSAGE_SENT_EVENT, event).await;

        Ok(message_id)
    }
}

#[async_trait]
impl<S> Protocol for BasicMessageProtocol<S>
where
    S: Storage<String, BasicMessageRecord> + Clone + 'static,
{
    fn protocol_name(&self) -> &'static str {
        PROTOCOL_NAME
    }

    fn protocol_version(&self) -> &'static str {
        PROTOCOL_VERSION
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        vec![self]
    }
}

#[async_trait]
impl<S> MessageHandler for BasicMessageProtocol<S>
where
    S: Storage<String, BasicMessageRecord> + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &[MESSAGE_TYPE]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        debug!("Handling basic message: {:?}", msg);

        // Parse the message content
        let content: BasicMessageContent = match serde_json::from_value(msg.body.clone()) {
            Ok(content) => content,
            Err(e) => {
                return protocol::Snafu {
                    details: format!("Failed to parse basic message content: {}", e),
                }
                .fail();
            }
        };

        let connection_id = match msg.from {
            Some(from) => from, // TODO: Replace by getting connection from sender DID
            None => {
                return protocol::Snafu {
                    details: "Message has no sender (from field)".to_string(),
                }
                .fail();
            }
        };

        let event = Event::MessageReceived {
            message_id: msg.id,
            thread_id: msg.thid,
            parent_thread_id: msg.pthid,
            connection_id,
            content: content.content,
            created_time: msg.created_time,
        };

        // Emit message received event
        self.event_emitter.emit(MESSAGE_RECEIVED_EVENT, event).await;

        Ok(())
    }
}
