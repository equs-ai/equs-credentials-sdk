use async_trait::async_trait;

use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::state_machine::StateMachine;

/// Receiver of unpacked messages; the supported types are trailing type segments such as
/// `offer-credential`, which must not overlap within a protocol.
#[async_trait]
pub trait MessageHandler: Sync + Send {
    /// Get the message types this handler accepts
    ///
    /// # Returns
    /// The trailing message type segments, e.g. `offer-credential`.
    fn supported_message_types(&self) -> &[&str];

    /// Handle an incoming message
    ///
    /// # Arguments
    /// * `msg` - the unpacked [`Message`], of a supported type
    ///
    /// # Errors
    /// * [protocol::Error] - the message could not be processed
    async fn handle(&self, msg: Message) -> protocol::Result<()>;
}

/// Message Handler with StateMachine capability; wrap it in [`StatefulMessageHandlerWrapper`] to
/// register as a [`MessageHandler`]. New state is persisted only after `on_state_transition` runs.
#[async_trait]
pub trait StatefulMessageHandler {
    /// Get the message types this handler accepts
    ///
    /// # Returns
    /// The trailing message type segments this handler accepts.
    fn supported_message_types(&self) -> &[&str];

    /// The protocol state machine.
    type StateMachine: StateMachine;

    /// Handle an incoming message
    ///
    /// # Arguments
    /// * `message` - The [`Message`] to handle
    ///
    /// # Errors
    /// * [protocol::Error] - validation failed, or the event could not be dispatched
    async fn handle(&self, message: Message) -> protocol::Result<()> {
        // Validate incoming DIDComm message
        self.validate_message(&message).await?;

        self.trigger_event(message.clone().try_into()?).await
    }

    /// Process a protocol-specific event through the state machine
    ///
    /// # Arguments
    /// * `event` - A protocol specific event
    ///
    /// # Errors
    /// * [protocol::Error] - the event could not be processed, or the new state not handled
    async fn trigger_event(
        &self,
        event: <<Self as StatefulMessageHandler>::StateMachine as StateMachine>::Event,
    ) -> protocol::Result<()> {
        let new_state = self.state_machine().process_event(event.clone()).await?;

        let message: Option<Message> = event.try_into()?;

        if let Some(message) = message {
            self.send_message(message).await?;
        }

        self.on_state_transition(new_state.clone()).await?;

        self.state_machine().change_state(new_state).await?;

        Ok(())
    }

    /// Validate an incoming message
    ///
    /// # Arguments
    /// * `message` - the DIDComm [`Message`] to validate
    ///
    /// # Errors
    /// * [protocol::Error] - returned to reject the message
    async fn validate_message(&self, message: &Message) -> protocol::Result<()>;

    /// Send a message the state transition produced
    ///
    /// # Arguments
    /// * `message` - the [`Message`] to send
    ///
    /// # Errors
    /// * [protocol::Error] - the message could not be sent
    async fn send_message(&self, message: Message) -> protocol::Result<()>;

    /// Get the state machine this handler drives
    ///
    /// # Returns
    /// The [`StatefulMessageHandler::StateMachine`] this handler drives.
    fn state_machine(&self) -> &Self::StateMachine;

    /// Handle actions triggered by a state change, before the new state is persisted.
    ///
    /// # Arguments
    /// * `new_state` - the [`StateMachine::State`] resulting from the transition
    ///
    /// # Errors
    /// * [protocol::Error] - leaves the stored state unchanged
    async fn on_state_transition(
        &self,
        new_state: <<Self as StatefulMessageHandler>::StateMachine as StateMachine>::State,
    ) -> protocol::Result<()>;
}

pub struct StatefulMessageHandlerWrapper<SM: StateMachine>(
    Box<dyn StatefulMessageHandler<StateMachine = SM> + Send + Sync>,
);

impl<SM: StateMachine> StatefulMessageHandlerWrapper<SM> {
    pub fn new<T>(handler: T) -> Self
    where
        T: StatefulMessageHandler<StateMachine = SM> + Send + Sync + 'static,
    {
        Self(Box::new(handler))
    }
}

#[async_trait]
impl<SM: StateMachine> MessageHandler for StatefulMessageHandlerWrapper<SM> {
    fn supported_message_types(&self) -> &[&str] {
        self.0.supported_message_types()
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        self.0.handle(msg).await
    }
}
