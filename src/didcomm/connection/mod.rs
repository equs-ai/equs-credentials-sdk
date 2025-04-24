use crate::did::DID;
use crate::storage::Storage;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use common_macros::DebugError;
use didcomm::Attachment;
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Error>;

#[async_trait]
pub trait Connection: Send + Sync {
    /// Create a new connection
    async fn create_connection(
        &self,
        my_did: &DID,
        create_options: CreateOptions,
    ) -> Result<ConnectionRecord>;

    /// Update a connection
    async fn update_connection(&self, connection: ConnectionRecord) -> Result<()>;

    async fn get_connection(&self, id: &str) -> Result<ConnectionRecord>;
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    #[default]
    Initial,
    Invited,
    Abandoned,
    Completed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Initial => write!(f, "initial"),
            ConnectionState::Invited => write!(f, "invited"),
            ConnectionState::Completed => write!(f, "completed"),
            ConnectionState::Abandoned => write!(f, "abandoned"),
        }
    }
}

/// Role of the agent in the connection
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionRole {
    #[default]
    Inviter,
    Invitee,
}

/// Connection record representing a connection with another agent
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub id: String,
    pub state: ConnectionState,
    pub role: ConnectionRole,
    pub my_did: String,
    pub auto_accept: bool,
    pub their_did: Option<String>,
    pub parent_thread_id: Option<String>,
    pub thread_id: Option<String>,
    pub their_endpoint: Option<String>,
    pub label: Option<String>,
    pub alias: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateOptions {
    pub role: ConnectionRole,
    pub state: ConnectionState,
    pub label: Option<String>,
    pub alias: Option<String>,
    pub auto_accept: Option<bool>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ConnectionRecord {
    /// Check if connection is in ready state
    pub fn is_ready(&self) -> bool {
        self.state == ConnectionState::Completed
    }
}

/// Query parameters for finding connections
#[derive(Debug, Default, Clone)]
pub struct ConnectlonQuery {
    pub id: Option<String>,
    pub thread_id: Option<String>,
    pub my_did: Option<String>,
    pub their_did: Option<String>,
    pub state: Option<ConnectionState>,
    pub label: Option<String>,
}

/// Connection invitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub label: Option<String>,
    pub from: String,
    pub body: InvitationBody,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationBody {
    pub goal: String,
    pub goal_code: String,
    pub accept: Vec<String>,
}

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Storage service error"))]
    Storage {
        source: crate::storage::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Connection with id = {id} not found"))]
    ConnectionNotFound { id: String },
}

#[derive(Clone)]
/// The ConnectionService service defines methods for managing connections
pub struct ConnectionService<S>
where
    S: Storage<String, ConnectionRecord> + Clone + 'static,
{
    storage: S,
}

impl<S> ConnectionService<S>
where
    S: Storage<String, ConnectionRecord> + Clone + 'static,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<S> Connection for ConnectionService<S>
where
    S: Storage<String, ConnectionRecord> + Clone + 'static,
{
    /// Create a new connection
    async fn create_connection(
        &self,
        my_did: &DID,
        create_options: CreateOptions,
    ) -> Result<ConnectionRecord> {
        let connection = ConnectionRecord {
            id: Uuid::new_v4().to_string(),
            state: ConnectionState::Initial,
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
    async fn update_connection(&self, connection: ConnectionRecord) -> Result<()> {
        self.storage
            .put(connection.id.to_owned(), connection)
            .await
            .context(StorageSnafu)
    }
    /// Get a connection by ID
    async fn get_connection(&self, id: &str) -> Result<ConnectionRecord> {
        let connection = self
            .storage
            .get(&id.to_string())
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| ConnectionNotFoundSnafu { id: id.to_string() }.build())?;

        Ok(connection)
    }
}
