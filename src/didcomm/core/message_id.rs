use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MessageId(pub String);

impl MessageId {
    #[cfg(test)]
    pub fn test_id() -> MessageId {
        MessageId(String::from("testid"))
    }

    pub fn new() -> MessageId {
        MessageId::default()
    }

    pub fn value(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for MessageId {
    #[cfg(test)]
    fn default() -> MessageId {
        MessageId::test_id()
    }

    #[cfg(not(test))]
    fn default() -> MessageId {
        MessageId(uuid::Uuid::new_v4().to_string())
    }
}
