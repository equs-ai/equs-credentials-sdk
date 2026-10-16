use async_trait::async_trait;
use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use tracing::{debug, instrument};

use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::protocol_registry::ProtocolRegistry;
use crate::didcomm::core::{message_type, protocol, protocol_registry};

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Cannot handle the message type: {type_}"))]
    HandlerNotFound { type_: String },
    #[snafu(display("Protocol error"))]
    Protocol {
        source: protocol::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Protocol registry error"))]
    ProtocolRegistry {
        source: protocol_registry::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Incorrect message type"))]
    IncorrectMessageType {
        source: message_type::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Interface for dispatching messages to handlers
#[async_trait]
pub trait Dispatcher: Send + Sync {
    /// Dispatch a message to the appropriate handler
    ///
    /// # Arguments
    /// * `msg` - The message to dispatch
    ///
    /// # Errors
    ///
    /// [Error] - fails to dispatch the message.
    async fn dispatch(&self, msg: Message) -> Result<()>;
}

/// Default implementation of the Dispatcher trait
pub struct DispatcherService {
    protocol_registry: ProtocolRegistry,
}

impl DispatcherService {
    /// Create a new Default Dispatcher
    ///
    /// # Arguments
    /// * `handler_registry` - Registry of message handlers
    pub fn new(protocol_registry: ProtocolRegistry) -> Self {
        Self { protocol_registry }
    }
}

#[async_trait]
impl Dispatcher for DispatcherService {
    #[instrument(skip(self, msg), fields(message_id = msg.id, message_type = msg.type_))]
    async fn dispatch(&self, msg: Message) -> Result<()> {
        let (_, family, version, type_) =
            message_type::parse_message_type(&msg.type_).context(IncorrectMessageTypeSnafu)?;

        let protocol = self
            .protocol_registry
            .get_protocol(&family, &version)
            .await
            .context(ProtocolRegistrySnafu)?;

        debug!(
            "Handling message with handler for message type {}",
            &msg.type_
        );

        let message_handlers = protocol.get_message_handlers();

        let handler = message_handlers
            .iter()
            .find(|handler| handler.supported_message_types().contains(&type_.as_str()))
            .ok_or_else(|| HandlerNotFoundSnafu { type_ }.build())?;

        handler.handle(msg).await.context(ProtocolSnafu)
    }
}
