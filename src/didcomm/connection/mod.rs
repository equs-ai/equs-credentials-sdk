#[cfg(any(test, feature = "in-memory"))]
pub mod in_mem;
#[cfg(test)]
pub mod test_utils;

use crate::did::DID;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use common_macros::DebugError;
use didcomm::Attachment;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use std::collections::HashMap;
use std::fmt;

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
    #[snafu(display("Connection is not in the completed state"))]
    ConnectionNotCompleted,
}

pub type Result<T> = std::result::Result<T, Error>;

#[async_trait]
pub trait ConnectionService: Send + Sync {
    /// Create a new connection
    async fn create_connection(
        &self,
        my_did: &DID,
        create_options: CreateOptions,
    ) -> Result<ConnectionRecord>;

    /// Update a connection
    async fn update_connection(&self, connection: ConnectionRecord) -> Result<()>;

    /// Get a connection by ID
    async fn get_connection(&self, id: &str) -> Result<ConnectionRecord>;
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    #[default]
    Initial,
    Invited,
    Accepted,
    Abandoned,
    Completed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Initial => write!(f, "initial"),
            ConnectionState::Invited => write!(f, "invited"),
            ConnectionState::Accepted => write!(f, "accepted"),
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

impl ConnectionRecord {
    pub fn their_did(&self) -> Result<String> {
        self.their_did
            .clone()
            .ok_or_else(|| ConnectionNotCompletedSnafu.build())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateOptions {
    pub role: ConnectionRole,
    pub state: ConnectionState,
    pub label: Option<String>,
    pub alias: Option<String>,
    pub auto_accept: Option<bool>,
    pub pthid: String,
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
pub struct ConnectionQuery {
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
