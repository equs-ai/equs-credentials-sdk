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

/// Protocol trait defining methods for a DIDComm protocol; the name and version must match the
/// message type URIs it handles, and the registry rejects a duplicate name/version pair.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Get the protocol name
    ///
    /// # Returns
    /// The protocol family, e.g. `issue-credential`.
    fn protocol_name(&self) -> &'static str;

    /// Get the protocol version
    ///
    /// # Returns
    /// The protocol version, e.g. `3.0`.
    fn protocol_version(&self) -> &'static str;

    /// Get protocol's message handlers
    ///
    /// # Returns
    /// The [`MessageHandler`]s to try, in order, for a message of this protocol.
    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler>;
}
