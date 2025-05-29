pub mod message_handler;
pub mod state_machine;

use async_trait::async_trait;
use common_macros::DebugError;
use message_handler::MessageHandler;
use snafu::Snafu;
use std::fmt::Debug;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[snafu(display("Protocol error: {details}"))]
pub struct Error {
    pub details: String,
}

/// Protocol trait defining methods for a DIDComm protocol
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Get the protocol name
    fn protocol_name(&self) -> &'static str;

    /// Get the protocol version
    fn protocol_version(&self) -> &'static str;

    /// Get protocol's message handlers
    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler>;
}
