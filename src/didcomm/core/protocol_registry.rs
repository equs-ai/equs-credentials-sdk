use async_lock::RwLock;
use common_macros::DebugError;
use snafu::Snafu;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::info;

use crate::didcomm::core::protocol::Protocol;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Protocol is already in use: {details}"))]
    AlreadyRegistered { details: String },
    #[snafu(display("Message handler registration error: {details}"))]
    HandlerRegistrationError { details: String },
    #[snafu(display("Protocol not found: {name}"))]
    ProtocolNotFound { name: String },
    #[snafu(display("{details}"))]
    Event { details: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Protocol version entry
struct ProtocolEntry {
    name: String,
    version: String,
    protocol: Arc<dyn Protocol>,
}

/// Protocol Registry for managing protocol implementations
#[derive(Clone)]
pub struct ProtocolRegistry {
    protocols: Arc<RwLock<HashMap<String, ProtocolEntry>>>,
}

impl ProtocolRegistry {
    /// Create a new protocol registry
    pub fn new() -> Self {
        Self {
            protocols: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Build the registration key
    fn build_registration_key(name: &str, version: &str) -> String {
        format!("{}:{}", name.to_lowercase(), version.to_lowercase())
    }
}

impl ProtocolRegistry {
    /// Register a protocol
    ///
    /// # Arguments
    /// * `protocol` - The protocol to register
    ///
    /// # Errors
    ///
    /// * [Error::AlreadyRegistered] if protocol is already registered
    pub async fn register_protocol(&self, protocol: impl Protocol + 'static) -> Result<()> {
        let protocol_name = protocol.protocol_name();
        let protocol_version = protocol.protocol_version();

        info!(
            "Registering protocol: {} v{}",
            protocol_name, protocol_version
        );

        let key = Self::build_registration_key(protocol_name, protocol_version);

        // Check if already registered
        {
            let protocols = self.protocols.read().await;
            if protocols.contains_key(&key) {
                AlreadyRegisteredSnafu {
                    details: format!("{}:{}", protocol_name, protocol_version),
                }
                .fail()?;
            }
        }

        // Create the protocol entry
        let entry = ProtocolEntry {
            name: protocol_name.to_string(),
            version: protocol_version.to_string(),
            protocol: Arc::new(protocol),
        };

        // Register the protocol
        {
            let mut protocols = self.protocols.write().await;
            protocols.insert(key.clone(), entry);
        }

        info!(
            "Protocol {} v{} registered successfully",
            protocol_name, protocol_version
        );

        Ok(())
    }

    /// Get a protocol by name
    ///
    /// # Arguments
    /// * `name` - The name of the protocol
    /// * `version` - The version of the protocol
    ///
    /// # Returns
    /// * `&dyn Protocol` if found
    ///
    /// # Errors
    ///
    /// * [Error::ProtocolNotFound] if protocol is not found
    pub async fn get_protocol(&self, name: &str, version: &str) -> Result<Arc<dyn Protocol>> {
        let key = Self::build_registration_key(name, version);

        let protocols = self.protocols.read().await;
        let entry = protocols
            .get(&key)
            .ok_or_else(|| ProtocolNotFoundSnafu { name }.build())?;

        Ok(entry.protocol.clone())
    }

    /// Check if a protocol is registered
    ///
    /// # Arguments
    /// * `name` - The name of the protocol
    ///
    /// # Returns
    /// * `true` if registered
    /// * `false` if not registered
    pub async fn has_protocol(&self, name: &str, version: &str) -> bool {
        let key = Self::build_registration_key(name, version);

        let protocols = self.protocols.read().await;
        protocols.contains_key(&key)
    }
}
