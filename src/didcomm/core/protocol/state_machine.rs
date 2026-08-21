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

/// Persistent state of a protocol instance, keyed by thread identifier; `process_event` computes
/// the next state without applying it and the caller persists it through `change_state`.
#[async_trait]
pub trait StateMachine: Send + Sync {
    /// State stored per thread.
    type State: Clone + Debug + Send + Sync + 'static;

    /// Event driving transitions.
    type Event: Event + 'static;

    /// Returns the current state.
    ///
    /// # Arguments
    /// * `thid` - thread identifier
    ///
    /// # Returns
    /// The [`StateMachine::State`] for that thread, or `None` if the thread is unknown.
    ///
    /// # Errors
    /// * [protocol::Error] - the state could not be loaded
    async fn state(&self, thid: Option<String>) -> protocol::Result<Option<Self::State>>;

    /// Process the event through the state machine
    ///
    /// # Arguments
    /// * `event` - the [`StateMachine::Event`] to process
    ///
    /// # Returns
    /// The [`StateMachine::State`] the event leads to, not yet persisted.
    ///
    /// # Errors
    /// * [protocol::Error] - the event is illegal in the current state
    async fn process_event(&self, event: Self::Event) -> protocol::Result<Self::State>;

    /// Change to a new state
    ///
    /// # Arguments
    /// * `new_state` - the new [`StateMachine::State`], persisted under the thread it carries
    ///
    /// # Errors
    /// * [protocol::Error] - the state could not be persisted
    async fn change_state(&self, new_state: Self::State) -> protocol::Result<()>;
}
