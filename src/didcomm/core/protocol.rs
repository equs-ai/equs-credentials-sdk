use async_trait::async_trait;
use common_macros::DebugError;
use snafu::Snafu;
use std::fmt::Debug;

use crate::didcomm::core::envelope::Message;

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

    /// Handle a message
    ///
    /// # Arguments
    /// * `msg` - The message to handle
    ///
    /// # Errors
    ///
    /// * [Error] - fails to handle the message.
    async fn handle(&self, msg: Message) -> Result<()>;
}

#[derive(Clone, Debug)]
pub enum MessageDirection {
    Send,
    Receive,
}

pub trait Event: Clone + Debug + Send + Sync {
    /// Convert a Message Type and Direction to an event that can be processed by the state machine
    fn from_message(direction: MessageDirection, message: &Message) -> Result<Self>;
}

/// Trait to extend Protocol with StateMachine capability
#[async_trait]
pub trait StatefulProtocol: Protocol {
    /// The protocol state machine.
    type StateMachine: StateMachine;

    /// Dispatch an incoming message.
    ///
    /// # Arguments
    /// * `msg` - The message to handle
    ///
    /// # Errors
    ///
    /// Returns an error if fails to dispatch the message.
    async fn dispatch_incoming_message(&self, message: Message) -> Result<()> {
        // Validate incoming DIDComm message
        self.validate_message(&message).await?;

        self.dispatch_message(MessageDirection::Receive, message)
            .await
    }

    /// Dispatch a message into the state machine with a given direction.
    ///
    /// # Arguments
    ///
    /// * `direction` – whether this is a send or receive event  
    /// * `message` – the DIDComm message to feed into the state machine  
    ///
    /// # Errors
    ///
    /// Returns an error if the state machine cannot process the event, or if
    /// handling the resulting state fails.
    async fn dispatch_message(&self, direction: MessageDirection, message: Message) -> Result<()> {
        // Create event
        let event =
            <<Self as StatefulProtocol>::StateMachine as StateMachine>::Event::from_message(
                direction.clone(),
                &message,
            )?;

        let old_state = self.state_machine().state(message.thid.to_owned()).await?;

        // Process the event through State Machine
        let new_state = self
            .state_machine()
            .process_event(message.thid.to_owned(), event)
            .await?;

        self.on_state_transition(old_state, new_state, direction, message)
            .await?;

        Ok(())
    }

    /// Validate an incoming message.
    ///
    /// # Arguments
    ///
    /// * `message` – a reference to the DIDComm message
    ///
    /// # Errors
    ///
    /// Return an error to reject the message.
    async fn validate_message(&self, message: &Message) -> Result<()>;

    fn state_machine(&self) -> &Self::StateMachine;

    /// Handle actions triggered by a state change.
    ///
    /// # Arguments
    ///
    /// * `new_state` – the state resulting from the transition
    /// * `message` – the original message that caused the transition
    ///
    /// # Errors
    ///
    /// Returns an error if fails to handle the message.
    async fn on_state_transition(
        &self,
        old_state: Option<<<Self as StatefulProtocol>::StateMachine as StateMachine>::State>,
        new_state: <<Self as StatefulProtocol>::StateMachine as StateMachine>::State,
        message_direction: MessageDirection,
        message: Message,
    ) -> Result<()>;
}

#[async_trait]
pub trait StateMachine: Send + Sync {
    type State: Clone + Debug + Send + Sync + 'static;

    type Event: Event + 'static;

    /// Returns the current state.
    async fn state(&self, thid: Option<String>) -> Result<Option<Self::State>>;

    /// Process the event through the state machine
    async fn process_event(&self, thid: Option<String>, event: Self::Event) -> Result<Self::State>;
}
