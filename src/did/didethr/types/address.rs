use serde::{Deserialize, Serialize};

const PREFIX: &str = "0x";
const NULL_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Address(String);

impl Address {
    pub fn as_blockchain_id(&self, chain_id: u64) -> String {
        format!("eip155:{}:{}", chain_id, self.as_ref())
    }

    pub fn is_null(&self) -> bool {
        self.as_ref() == NULL_ADDRESS
    }
}

impl From<&str> for Address {
    fn from(address: &str) -> Self {
        let address = if address.starts_with("did:ethr") {
            address.split(':').next_back().unwrap_or(address)
        } else {
            address
        };

        if address.starts_with(PREFIX) {
            Address(address.to_string())
        } else {
            Address(format!("{}{}", PREFIX, address))
        }
    }
}

impl AsRef<str> for Address {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
