use async_trait::async_trait;
use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use tracing::{debug, instrument};

use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::parsed_message_type::ParsedMessageType;
use crate::didcomm::core::protocol_registry::ProtocolRegistry;
use crate::didcomm::core::{parsed_message_type, protocol, protocol_registry};

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
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
        source: parsed_message_type::Error,
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
        let parsed_message_type =
            ParsedMessageType::from_message_type(&msg.type_).context(IncorrectMessageTypeSnafu)?;

        let handler = self
            .protocol_registry
            .get_protocol(
                &parsed_message_type.protocol_name,
                &parsed_message_type.protocol_version,
            )
            .await
            .context(ProtocolRegistrySnafu)?;

        debug!("Handling message with handler");
        handler.handle(msg).await.context(ProtocolSnafu)?;

        Ok(())
    }
}
