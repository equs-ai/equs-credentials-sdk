#[cfg(feature = "didcomm-http-transport")]
pub mod http;
#[cfg(test)]
pub mod mock;

use async_trait::async_trait;
use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use std::fmt;
use url::Url;

use crate::didcomm::core::message_receiver::MessageReceiver;

pub type Result<T> = std::result::Result<T, Error>;

/// Error types for transports
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Url parse error"))]
    Url {
        source: url::ParseError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Configuration error: {details}"))]
    Configuration { details: String },
    #[snafu(display("Transport is not supported error: {details}"))]
    UnsupportedTransport { details: String },
    #[snafu(display("Network error: {details}"))]
    Network { details: String },
    #[snafu(display("Transport is already running"))]
    AlreadyRunning,
    #[snafu(display("Transport is not running"))]
    NotRunning,
    #[snafu(display("Payload decoding error: {details}"))]
    Decoding { details: String },
}

/// Transport type (HTTP, WebSocket, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// HTTP transport
    Http,
    /// WebSocket transport
    WebSocket,
    /// Custom transport
    Custom(&'static str),
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Http => write!(f, "http"),
            TransportType::WebSocket => write!(f, "ws"),
            TransportType::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Outbound message to be sent by transport
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub endpoint: String,
    pub payload: Vec<u8>,
    pub content_type: String,
    pub accept_content_type: String,
}

impl OutboundMessage {
    /// Create a new outbound message
    pub fn new(
        endpoint: String,
        payload: Vec<u8>,
        content_type: String,
        accept_content_type: String,
    ) -> Self {
        Self {
            endpoint,
            payload,
            content_type,
            accept_content_type,
        }
    }

    /// Get the endpoint URL
    pub fn endpoint_url(&self) -> Result<Url> {
        let url = Url::parse(&self.endpoint).context(UrlSnafu)?;

        Ok(url)
    }
}

/// Response from sending an outbound message
#[derive(Debug, Clone)]
pub struct OutboundMessageResponse {
    pub status: u16,
    pub body: Option<Vec<u8>>,
    pub headers: Vec<(String, String)>,
}

/// Interface for an inbound transport; owns its listening task and passes each received payload
/// verbatim to [`MessageReceiver::receive_message`] without unpacking it.
#[async_trait]
pub trait InboundTransport: Send + Sync {
    /// Get the type of transport
    ///
    /// # Returns
    /// The [TransportType] of this transport.
    fn transport_type(&self) -> TransportType;

    /// Start the transport and begin listening for incoming messages
    ///
    /// # Arguments
    /// * `message_receiver` - [`MessageReceiver`] given a packed message, unpacks it, and dispatches it to the appropriate handler
    ///
    /// # Errors
    /// * [`Error::AlreadyRunning`] - the transport is already listening
    async fn start(&self, message_receiver: MessageReceiver) -> Result<()>;

    /// Stop the transport and stop listening for incoming messages
    ///
    /// # Errors
    /// * [`Error::NotRunning`] - the transport was not listening
    async fn stop(&self) -> Result<()>;

    /// Check if the transport is running
    ///
    /// # Returns
    /// `true` while listening.
    async fn is_running(&self) -> bool;

    /// Get the endpoint where the transport is listening
    ///
    /// # Returns
    /// The endpoint the transport listens on.
    fn endpoint(&self) -> &str;
}

/// Interface for an outbound transport; transmits the payload unmodified and rejects an endpoint
/// scheme that fails `supports_scheme` with [`Error::UnsupportedTransport`].
#[async_trait]
pub trait OutboundTransport: Send + Sync {
    /// Get the type of transport
    ///
    /// # Returns
    /// The [TransportType] of this transport.
    fn transport_type(&self) -> TransportType;

    /// Send a message via this transport
    ///
    /// # Arguments
    /// * `message` - The [`OutboundMessage`] to send
    ///
    /// # Returns
    /// The [OutboundMessageResponse] from the endpoint.
    ///
    /// # Errors
    /// * [`Error::UnsupportedTransport`] - the endpoint scheme fails `supports_scheme`
    /// * [`Error::Network`] - delivery failed
    async fn send_message(&self, message: OutboundMessage) -> Result<OutboundMessageResponse>;

    /// Check if this transport supports the given URL scheme
    ///
    /// # Arguments
    /// * `url` - The URL to check
    ///
    /// # Returns
    /// `true` if this transport handles the URL's scheme.
    fn supports_scheme(&self, url: &Url) -> bool;

    /// Start the transport, initializing any resources it needs
    ///
    /// # Errors
    /// * [Error] - the transport could not be started
    async fn start(&self) -> Result<()>;

    /// Stop the transport, releasing any resources it used
    ///
    /// # Errors
    /// * [Error] - the transport could not be stopped
    async fn stop(&self) -> Result<()>;
}
