use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu, ensure};
use std::sync::Arc;
use tracing::{debug, instrument};

use crate::didcomm::core::dispatcher::Dispatcher;
use crate::didcomm::core::envelope::EnvelopeService;
use crate::didcomm::core::{dispatcher, envelope};

pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during message receiving
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Dispatch error"))]
    Dispatch {
        source: dispatcher::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Envelope service error"))]
    Envelope {
        source: envelope::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Parse error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Message `from` is not authenticated by authcrypt or a signature"))]
    UnauthenticatedSender {
        #[snafu(implicit)]
        location: Location,
    },
}

/// Configuration options for the `DefaultMessageReceiver`
#[derive(Clone, Debug)]
pub struct MessageReceiverConfig {
    pub max_message_size: usize,
    pub skip_invalid_messages: bool,
}

impl Default for MessageReceiverConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            skip_invalid_messages: false,
        }
    }
}

/// The `MessageReceiver` for receiving and processing DIDComm messages
///
/// It is responsible for:
/// 1. Receiving encrypted/packed messages
/// 2. Unpacking them using the `EnvelopeService`
/// 3. Dispatching the messages to the appropriate handlers
#[derive(Clone)]
pub struct MessageReceiver {
    envelope_service: EnvelopeService,
    dispatcher: Arc<dyn Dispatcher>,
    config: MessageReceiverConfig,
}

impl MessageReceiver {
    /// Creates a new `MessageReceiverService` with the required components
    ///
    /// # Arguments
    /// * `envelope_service` - Service for packing/unpacking messages
    /// * `dispatcher` - Component for routing messages to handlers
    /// * `config` - Configuration options
    pub fn new(
        envelope_service: EnvelopeService,
        dispatcher: impl Dispatcher + 'static,
        config: MessageReceiverConfig,
    ) -> Self {
        Self {
            envelope_service,
            dispatcher: Arc::new(dispatcher),
            config,
        }
    }
}

impl MessageReceiver {
    /// Receives a packed message, unpacks it, and dispatches it to the appropriate handler
    ///
    /// A dispatched message's `from`, when set, is the authenticated sender: handlers receive no
    /// envelope metadata and rely on this.
    ///
    /// # Arguments
    /// * `packed_msg` - The raw, packed message bytes
    ///
    /// # Errors
    ///
    /// * [Error::Envelope] - fails to pack/unpack the message.
    /// * [Error::UnauthenticatedSender] - `from` is set but neither authcrypt nor a signature
    ///   authenticated it.
    /// * [Error::Dispatch] - fails to dispatch the message.
    #[instrument(skip(self, packed_msg), fields(message_size = packed_msg.len()))]
    pub async fn receive_message(&self, packed_msg: &[u8]) -> Result<()> {
        //TODO: Replace and fix issue while trying with below method call
        // let packed_msg = serde_json::from_slice(packed_msg).context(ParseSnafu)?;
        let message_str = String::from_utf8_lossy(packed_msg);
        // Unpack the message using the envelope service
        let (message, metadata) = self
            .envelope_service
            .unpack(&message_str, &Default::default())
            .await
            .context(EnvelopeSnafu)?;

        ensure!(
            message.from.is_none() || metadata.authenticated,
            UnauthenticatedSenderSnafu
        );

        debug!("Processing unpacked message with ID: {}", message.id);
        self.dispatcher
            .dispatch(message)
            .await
            .context(DispatchSnafu)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    use crate::did::didpeer::DIDPeer;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DID, VerificationMethodKey, VerificationRelationshipType};
    use crate::didcomm::core::dispatcher::{self, Dispatcher};
    use crate::didcomm::core::envelope::{EnvelopeService, Message, PackEncryptedOptions};
    use crate::didcomm::core::message_receiver::{Error, MessageReceiver};
    use crate::inmem::kms::LocalKms;
    use crate::kms::{KeyType, Kms};

    #[derive(Clone, Default)]
    struct RecordingDispatcher(Arc<Mutex<Vec<Message>>>);

    #[async_trait]
    impl Dispatcher for RecordingDispatcher {
        async fn dispatch(&self, msg: Message) -> dispatcher::Result<()> {
            self.0.lock().unwrap().push(msg);
            Ok(())
        }
    }

    #[tokio::test]
    async fn receive_message_dispatches_authcrypted_message() {
        let kms = LocalKms::new();
        let alice_did = create_did(&kms).await;
        let bob_did = create_did(&kms).await;
        let (envelope_service, dispatcher, receiver) = create_receiver(kms);

        let msg = example_message(Some(&alice_did));
        let (packed_msg, _) = envelope_service
            .pack_encrypted(
                &msg,
                &bob_did,
                Some(&alice_did),
                None,
                &PackEncryptedOptions::default(),
            )
            .await
            .unwrap();

        receiver
            .receive_message(packed_msg.as_bytes())
            .await
            .unwrap();

        assert_eq!(*dispatcher.0.lock().unwrap(), vec![msg]);
    }

    #[tokio::test]
    async fn receive_message_dispatches_plaintext_without_from() {
        let (envelope_service, dispatcher, receiver) = create_receiver(LocalKms::new());

        let msg = example_message(None);
        let packed_msg = envelope_service.pack_plaintext(&msg).await.unwrap();

        receiver
            .receive_message(packed_msg.as_bytes())
            .await
            .unwrap();

        assert_eq!(*dispatcher.0.lock().unwrap(), vec![msg]);
    }

    #[tokio::test]
    async fn receive_message_failed_with_unauthenticated_from() {
        let kms = LocalKms::new();
        let alice_did = create_did(&kms).await;
        let (envelope_service, dispatcher, receiver) = create_receiver(kms);

        let msg = example_message(Some(&alice_did));
        let packed_msg = envelope_service.pack_plaintext(&msg).await.unwrap();

        let err = receiver
            .receive_message(packed_msg.as_bytes())
            .await
            .unwrap_err();

        assert!(matches!(err, Error::UnauthenticatedSender { .. }));
        assert!(dispatcher.0.lock().unwrap().is_empty());
    }

    fn create_receiver(kms: LocalKms) -> (EnvelopeService, RecordingDispatcher, MessageReceiver) {
        let envelope_service = EnvelopeService::new(kms, UniversalResolver::default());
        let dispatcher = RecordingDispatcher::default();
        let receiver = MessageReceiver::new(
            envelope_service.clone(),
            dispatcher.clone(),
            Default::default(),
        );

        (envelope_service, dispatcher, receiver)
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
            &[],
        )
        .unwrap()
    }
}
