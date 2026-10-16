use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
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
    /// # Arguments
    /// * `packed_msg` - The raw, packed message bytes
    ///
    /// # Errors
    ///
    /// * [Error::Envelope] - fails to pack/unpack the message.
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

        debug!("Processing unpacked message with ID: {}", message.id);
        self.dispatcher
            .dispatch(message)
            .await
            .context(DispatchSnafu)?;

        Ok(())
    }
}
