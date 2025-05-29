use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};
use std::sync::Arc;
use time::OffsetDateTime;

use crate::did::universal::UniversalResolver;
use crate::did::DID;
use crate::didcomm::core::envelope;
use crate::didcomm::core::envelope::{EnvelopeService, Message};
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::transport;
use crate::didcomm::transport::{OutboundMessage, OutboundTransport};
use crate::utils::http::{MIME_DIDCOMM_ENCRYPTED_JSON, MIME_TYPE_TEXT_PLAIN};

pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during message sending.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Transport error"))]
    Transport {
        source: transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Envelope service error"))]
    EnvelopeService {
        source: envelope::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Parse error"))]
    Parse {
        source: serde_json::error::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

/// MessageSender is responsible for sending messages to other agents
#[derive(Clone)]
pub struct MessageSender {
    envelope_service: EnvelopeService,
    outbound_transport: Arc<dyn OutboundTransport>,
    event_emitter: EventEmitter<&'static str, Event>,
    did_resolver: UniversalResolver,
}

impl MessageSender {
    pub fn new(
        envelope_service: EnvelopeService,
        outbound_transport: impl OutboundTransport + 'static,
        event_emitter: EventEmitter<&'static str, Event>,
        did_resolver: UniversalResolver,
    ) -> Self {
        Self {
            envelope_service,
            outbound_transport: Arc::new(outbound_transport),
            event_emitter,
            did_resolver,
        }
    }
}

impl MessageSender {
    pub async fn send_message(
        &self,
        msg: &Message,
        to_did: DID,
        options: &SendOptions<'_>,
    ) -> Result<()> {
        // Pack the message
        let (packed_msg, metadata) = self
            .envelope_service
            .pack_encrypted(
                msg,
                &to_did,
                options.from,
                options.sign_by,
                // options.from.and_then(|s| Some(s.as_str())),
                // options.sign_by.and_then(|s| Some(s.as_str())),
                &didcomm::PackEncryptedOptions::default(),
            )
            .await
            .context(EnvelopeServiceSnafu)?;

        let outbound_message = OutboundMessage::new(
            metadata.messaging_service.unwrap().service_endpoint,
            packed_msg.as_bytes().to_vec(),
            MIME_DIDCOMM_ENCRYPTED_JSON.to_string(),
            MIME_TYPE_TEXT_PLAIN.to_string(),
        );

        let response = self
            .outbound_transport
            .send_message(outbound_message)
            .await
            .context(TransportSnafu)?;

        let event = Event::MessageSentEvent {
            id: msg.id.to_owned(),
            thread_id: msg.thid.to_owned(),
            parent_thread_id: msg.pthid.to_owned(),
            message_type: msg.type_.to_owned(),
            response_status_code: response.status,
            timestamp: OffsetDateTime::now_utc(),
        };

        self.event_emitter.emit(event.topic_name(), event).await;

        Ok(())
    }
}

#[derive(Default, Debug, Clone, Deserialize)]
pub struct SendOptions<'a> {
    pub from: Option<&'a str>,
    pub sign_by: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSentEvent {
    pub id: String,
    pub thread_id: Option<String>,
    pub parent_thread_id: Option<String>,
    pub message_type: String,
    pub timestamp: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    MessageSentEvent {
        id: String,
        thread_id: Option<String>,
        parent_thread_id: Option<String>,
        message_type: String,
        response_status_code: u16,
        timestamp: OffsetDateTime,
    },
}

const MESSAGE_SENT_EVENT: &str = "MessageSentEvent";
impl Event {
    pub fn topic_name(&self) -> &'static str {
        match self {
            Event::MessageSentEvent { .. } => MESSAGE_SENT_EVENT,
        }
    }
}
