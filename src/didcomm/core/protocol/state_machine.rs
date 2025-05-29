use async_trait::async_trait;
use std::fmt::Debug;

use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::protocol;

pub trait Event:
    Clone
    + Debug
    + Send
    + Sync
    + TryInto<Option<Message>, Error = protocol::Error>
    + TryFrom<Message, Error = protocol::Error>
{
}

impl<E> Event for E where
    E: Clone
        + Debug
        + Send
        + Sync
        + TryInto<Option<Message>, Error = protocol::Error>
        + TryFrom<Message, Error = protocol::Error>
{
}

pub struct StateTransition<S: Clone + Debug + Send + Sync + 'static> {
    pub next_state: S,
    pub out_message: Option<Message>,
}

#[async_trait]
pub trait StateMachine: Send + Sync {
    type State: Clone + Debug + Send + Sync + 'static;

    type Event: Event + 'static;

    /// Returns the current state.
    async fn state(&self, thid: Option<String>) -> protocol::Result<Option<Self::State>>;

    /// Process the event through the state machine
    async fn process_event(&self, event: Self::Event) -> protocol::Result<Self::State>;

    /// Change to a new state
    ///
    /// # Arguments
    ///
    /// * `new_state` – the new state
    ///
    /// # Errors
    ///
    /// Returns an error if fails to change the state.
    async fn change_state(&self, new_state: Self::State) -> protocol::Result<()>;
}
