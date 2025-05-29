use async_trait::async_trait;

use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::state_machine::StateMachine;

#[async_trait]
pub trait MessageHandler: Sync + Send {
    fn supported_message_types(&self) -> &[&str];

    async fn handle(&self, msg: Message) -> protocol::Result<()>;
}

/// Message Handler with StateMachine capability
#[async_trait]
pub trait StatefulMessageHandler {
    fn supported_message_types(&self) -> &[&str];

    /// The protocol state machine.
    type StateMachine: StateMachine;

    /// Handle an incoming message.
    ///
    /// # Arguments
    /// * `message` - The message to handle
    ///
    /// # Errors
    ///
    /// Returns an error if fails to dispatch the incoming message.
    async fn handle(&self, message: Message) -> protocol::Result<()> {
        // Validate incoming DIDComm message
        self.validate_message(&message).await?;

        self.trigger_event(message.clone().try_into()?).await
    }

    /// Process a protocol‐specific event through the state machine
    ///
    /// # Arguments
    ///
    /// * `thid` – A thread ID  
    /// * `event` – A protocol specific event  
    ///
    /// # Errors
    ///
    /// Returns an error if the state machine cannot process the event, or if
    /// handling the resulting state fails.
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

    /// Validate an incoming message.
    ///
    /// # Arguments
    ///
    /// * `message` – a reference to the DIDComm message
    ///
    /// # Errors
    ///
    /// Return an error to reject the message.
    async fn validate_message(&self, message: &Message) -> protocol::Result<()>;

    async fn send_message(&self, message: Message) -> protocol::Result<()>;

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
    /// Returns an error if fails to handle the state.
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
