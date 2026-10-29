use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};
use std::sync::Arc;
use time::OffsetDateTime;

use crate::did::DID;
use crate::did::universal::UniversalResolver;
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
    /// Packs `msg` for `to_did` and sends it over the outbound transport.
    ///
    /// The message is authcrypted as `options.from`, or as `msg.from` when `options.from` is
    /// unset, so a set `from` is always authenticated. It is anoncrypted only when both are unset.
    ///
    /// # Errors
    ///
    /// * [Error::EnvelopeService] - fails to pack the message, e.g. `options.from` and `msg.from`
    ///   name different DIDs.
    /// * [Error::Transport] - fails to send the packed message.
    pub async fn send_message(
        &self,
        msg: &Message,
        to_did: DID,
        options: &SendOptions<'_>,
    ) -> Result<()> {
        let from = options.from.or(msg.from.as_deref());

        // Pack the message
        let (packed_msg, metadata) = self
            .envelope_service
            .pack_encrypted(
                msg,
                &to_did,
                from,
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

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use url::Url;

    use crate::did::didpeer::{DIDPeer, DidPeerService};
    use crate::did::universal::UniversalResolver;
    use crate::did::{DID, VerificationMethodKey, VerificationRelationshipType};
    use crate::didcomm::core::envelope::{EnvelopeService, Message, UnpackMetadata};
    use crate::didcomm::core::event_emitter::EventEmitter;
    use crate::didcomm::core::message_sender::{Error, MessageSender, SendOptions};
    use crate::didcomm::transport::{
        self, OutboundMessage, OutboundMessageResponse, OutboundTransport, TransportType,
    };
    use crate::inmem::kms::LocalKms;
    use crate::kms::{KeyType, Kms};

    #[derive(Clone, Default)]
    struct RecordingTransport(Arc<Mutex<Vec<Vec<u8>>>>);

    #[async_trait]
    impl OutboundTransport for RecordingTransport {
        fn transport_type(&self) -> TransportType {
            TransportType::Http
        }

        async fn send_message(
            &self,
            message: OutboundMessage,
        ) -> transport::Result<OutboundMessageResponse> {
            self.0.lock().unwrap().push(message.payload);

            Ok(OutboundMessageResponse {
                status: 200,
                body: None,
                headers: vec![],
            })
        }

        fn supports_scheme(&self, url: &Url) -> bool {
            url.scheme() == "http"
        }

        async fn start(&self) -> transport::Result<()> {
            Ok(())
        }

        async fn stop(&self) -> transport::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn send_message_authcrypts_message_with_from() {
        let kms = LocalKms::new();
        let alice_did = create_did(&kms).await;
        let bob_did = create_did(&kms).await;
        let (envelope_service, transport, sender) = create_sender(kms);

        sender
            .send_message(
                &example_message(Some(&alice_did)),
                bob_did,
                &SendOptions::default(),
            )
            .await
            .unwrap();

        let metadata = unpack_sent(&envelope_service, &transport).await;
        assert!(metadata.authenticated);
        assert!(
            metadata
                .encrypted_from_kid
                .unwrap()
                .starts_with(&format!("{alice_did}#"))
        );
    }

    #[tokio::test]
    async fn send_message_anoncrypts_message_without_from() {
        let kms = LocalKms::new();
        let bob_did = create_did(&kms).await;
        let (envelope_service, transport, sender) = create_sender(kms);

        sender
            .send_message(&example_message(None), bob_did, &SendOptions::default())
            .await
            .unwrap();

        let metadata = unpack_sent(&envelope_service, &transport).await;
        assert!(!metadata.authenticated);
        assert!(metadata.encrypted_from_kid.is_none());
    }

    #[tokio::test]
    async fn send_message_failed_with_from_not_matching_message_from() {
        let kms = LocalKms::new();
        let alice_did = create_did(&kms).await;
        let bob_did = create_did(&kms).await;
        let eve_did = create_did(&kms).await;
        let (_, transport, sender) = create_sender(kms);

        let err = sender
            .send_message(
                &example_message(Some(&alice_did)),
                bob_did,
                &SendOptions {
                    from: Some(&eve_did),
                    sign_by: None,
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, Error::EnvelopeService { .. }));
        assert!(transport.0.lock().unwrap().is_empty());
    }

    fn create_sender(kms: LocalKms) -> (EnvelopeService, RecordingTransport, MessageSender) {
        let envelope_service = EnvelopeService::new(kms, UniversalResolver::default());
        let transport = RecordingTransport::default();
        let sender = MessageSender::new(
            envelope_service.clone(),
            transport.clone(),
            EventEmitter::new(),
            UniversalResolver::default(),
        );

        (envelope_service, transport, sender)
    }

    async fn unpack_sent(
        envelope_service: &EnvelopeService,
        transport: &RecordingTransport,
    ) -> UnpackMetadata {
        let payload = transport.0.lock().unwrap().pop().unwrap();
        let (_, metadata) = envelope_service
            .unpack(&String::from_utf8(payload).unwrap(), &Default::default())
            .await
            .unwrap();

        metadata
    }

    fn example_message(from: Option<&DID>) -> Message {
        let msg = Message::build(
            "example-id".to_owned(),
            "https://didcomm.org/basicmessage/2.0/message".to_owned(),
            json!({ "content": "example" }),
        );

        match from {
            Some(from) => msg.from(from.to_owned()).finalize(),
            None => msg.finalize(),
        }
    }

    async fn create_did(kms: &LocalKms) -> DID {
        let (_, kh) = kms
            .create_and_handle(KeyType::P256, Default::default())
            .await
            .unwrap();

        let service: DidPeerService = serde_json::from_value(json!({
            "id": "#didcomm-1",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": "http://127.0.0.1:8000",
                "accept": ["didcomm/v2"],
                "routingKeys": ["#key-0"]
            }
        }))
        .unwrap();

        DIDPeer::generate_did_peer4(
            &[VerificationMethodKey {
                key: &kh,
                verification_relationships: vec![
                    VerificationRelationshipType::Authentication,
                    VerificationRelationshipType::KeyAgreement,
                ]
                .into_iter()
                .collect(),
            }],
            &[service],
        )
        .unwrap()
    }
}
