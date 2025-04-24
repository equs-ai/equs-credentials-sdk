use async_lock::RwLock;
use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use std::sync::Arc;
use tracing::info;

use crate::did::DID;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::message_receiver::MessageReceiver;
use crate::didcomm::core::message_sender;
use crate::didcomm::core::message_sender::{MessageSender, SendOptions};
use crate::didcomm::transport;
use crate::didcomm::transport::{InboundTransport, OutboundTransport};

pub(super) const DIDCOMM_SCHEME: &str = "didcomm://";

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("DIDComm service initialization error: {details}"))]
    Initialization { details: String },
    #[snafu(display("DIDComm service shutting down error: {details}"))]
    ShutDown { details: String },
    #[snafu(display("Transport error"))]
    Transport {
        source: transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Connection error"))]
    ProtocolRegistry {
        source: crate::didcomm::core::protocol_registry::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Message sending error"))]
    MessageSender {
        source: message_sender::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// DIDComm Service config
#[derive(Debug, Clone)]
pub struct DIDCommServiceConfig {
    pub label: String,
    pub endpoint: String,
    pub auto_accept_connections: bool,
}

/// Initialization state for the API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DIDCommServiceState {
    Uninitialized,
    Initializing,
    Running,
    ShuttingDown,
    ShutDown,
}

/// Service for DIDComm operations
#[derive(Clone)]
pub struct DIDCommService {
    message_receiver: MessageReceiver,
    message_sender: MessageSender,
    inbound_transport: Arc<dyn InboundTransport>,
    outbound_transport: Arc<dyn OutboundTransport>,
    state: Arc<RwLock<DIDCommServiceState>>,
}

impl DIDCommService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_receiver: MessageReceiver,
        message_sender: MessageSender,
        inbound_transport: impl InboundTransport + 'static,
        outbound_transport: impl OutboundTransport + 'static,
    ) -> Self {
        Self {
            inbound_transport: Arc::new(inbound_transport),
            outbound_transport: Arc::new(outbound_transport),
            state: Arc::new(RwLock::new(DIDCommServiceState::Uninitialized)),
            message_receiver,
            message_sender,
        }
    }

    /// Private method to check if the Service is initialized
    ///
    /// # Returns
    /// * `Ok(())` if the Service is initialized
    /// * `Err(DIDCommAPIError::NotInitialized)` if the Service is not initialized
    async fn check_initialized(&self) -> Result<()> {
        let state = self.state.read().await;
        if *state != DIDCommServiceState::Running {
            InitializationSnafu {
                details: format!("DIDComm service initialization failed with {:?}", state),
            }
            .fail()?;
        }
        Ok(())
    }
}

impl DIDCommService {
    /// Initialize the DIDComm Service
    ///
    /// # Errors
    ///
    /// * [Error::Initialization] if Service is already initialized or initializing
    pub async fn initialize(&self) -> Result<()> {
        // Update state to initializing
        {
            let mut state = self.state.write().await;
            if *state != DIDCommServiceState::Uninitialized {
                InitializationSnafu {
                    details: "DIDComm service is already initialized or initializing".to_string(),
                }
                .fail()?;
            }
            *state = DIDCommServiceState::Initializing;
        }

        info!("Initializing DIDComm Service...");

        // Start all transports
        self.inbound_transport
            .start(self.message_receiver.clone())
            .await
            .context(TransportSnafu)?;
        self.outbound_transport
            .start()
            .await
            .context(TransportSnafu)?;

        // Update state to running
        {
            let mut state = self.state.write().await;
            *state = DIDCommServiceState::Running;
        }

        info!("DIDComm Service initialized successfully");

        Ok(())
    }

    /// Shut down the Service
    ///
    /// # Errors
    ///
    /// * [Error::ShutDown] if fails to shut down
    pub async fn shutdown(&self) -> Result<()> {
        // Update state to shutting down
        {
            let mut state = self.state.write().await;
            if *state != DIDCommServiceState::Running {
                ShutDownSnafu {
                    details: "DIDComm service is not running".to_string(),
                }
                .fail()?;
            }
            *state = DIDCommServiceState::ShuttingDown;
        }

        info!("Shutting down DIDComm API...");

        // Stop all transports
        self.inbound_transport
            .stop()
            .await
            .context(TransportSnafu)?;
        self.outbound_transport
            .stop()
            .await
            .context(TransportSnafu)?;

        // Update state to shut down
        {
            let mut state = self.state.write().await;
            *state = DIDCommServiceState::ShutDown;
        }

        info!("DIDComm API shut down successfully");

        Ok(())
    }

    /// Check if the Service is initialized
    ///
    /// # Returns
    /// * `true` if the Service is initialized
    /// * `false` otherwise
    pub async fn is_initialized(&self) -> bool {
        let state = self.state.read().await;
        *state == DIDCommServiceState::Running
    }

    /// Get the current state of the Service
    ///
    /// # Returns
    /// * The current state of the Service
    pub async fn state(&self) -> DIDCommServiceState {
        let state = self.state.read().await;
        *state
    }

    /// Send didcomm messages
    pub async fn send_message(
        &self,
        msg: &Message,
        to_did: DID,
        send_options: &SendOptions<'_>,
    ) -> Result<()> {
        self.message_sender
            .send_message(msg, to_did, send_options)
            .await
            .context(MessageSenderSnafu)
    }
}
