use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct Block(u64);

impl Block {
    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn is_none(&self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for Block {
    fn from(value: u64) -> Self {
        Block(value)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct BlockDetails {
    pub number: u64,
    pub timestamp: u64,
}
