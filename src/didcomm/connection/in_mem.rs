use async_trait::async_trait;
use chrono::Utc;
use snafu::ResultExt;

use crate::did::DID;
use crate::didcomm::connection::{
    ConnectionNotFoundSnafu, ConnectionRecord, ConnectionRole, ConnectionService, CreateOptions,
    StorageSnafu,
};
use crate::didcomm::core::message_id::MessageId;
use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;

#[derive(Clone)]
/// The ConnectionService service defines methods for managing connections
pub struct InMemConnectionService {
    storage: InMemStorage<String, ConnectionRecord>,
}

impl InMemConnectionService {
    pub fn new() -> Self {
        Self {
            storage: InMemStorage::new(),
        }
    }
}

#[async_trait]
impl ConnectionService for InMemConnectionService {
    /// Create a new connection
    async fn create_connection(
        &self,
        my_did: &DID,
        create_options: CreateOptions,
    ) -> crate::didcomm::connection::Result<ConnectionRecord> {
        let connection = ConnectionRecord {
            id: MessageId::new().to_string(),
            state: create_options.state,
            role: ConnectionRole::Inviter,
            my_did: my_did.to_string(),
            thread_id: None,
            their_did: None,
            parent_thread_id: None,
            their_endpoint: None,
            label: create_options.label,
            alias: create_options.alias,
            auto_accept: create_options.auto_accept.unwrap_or(true),
            metadata: create_options.metadata,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        self.storage
            .put(connection.id.to_owned(), connection.clone())
            .await
            .context(StorageSnafu)?;

        Ok(connection)
    }

    /// Update a connection
    async fn update_connection(
        &self,
        connection: ConnectionRecord,
    ) -> crate::didcomm::connection::Result<()> {
        self.storage
            .put(connection.id.to_owned(), connection)
            .await
            .context(StorageSnafu)
    }

    /// Get a connection by ID
    async fn get_connection(
        &self,
        id: &str,
    ) -> crate::didcomm::connection::Result<ConnectionRecord> {
        let connection = self
            .storage
            .get(&id.to_string())
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| ConnectionNotFoundSnafu { id: id.to_string() }.build())?;

        Ok(connection)
    }
}
