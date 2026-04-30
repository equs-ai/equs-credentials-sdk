use crate::did::didethr::types::{Address, Block};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum DidEvents {
    AttributeChangedEvent(DidAttributeChanged),
    DelegateChanged(DidDelegateChanged),
    OwnerChanged(DidOwnerChanged),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidAttributeChanged {
    pub identity: Address,
    pub name: String,
    pub value: Vec<u8>,
    pub valid_to: u64,
    pub previous_change: Block,
}

impl DidAttributeChanged {
    pub fn key(&self) -> String {
        format!("DidDocAttribute-{}-{:?}", self.name, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDelegateChanged {
    pub identity: Address,
    pub delegate: Address,
    pub delegate_type: Vec<u8>,
    pub valid_to: u64,
    pub previous_change: Block,
}

impl DidDelegateChanged {
    pub fn key(&self) -> String {
        format!(
            "DelegateChanged-{:?}-{}",
            self.delegate_type,
            self.delegate.as_ref()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidOwnerChanged {
    pub identity: Address,
    pub owner: Address,
    pub previous_change: Block,
}

impl DidOwnerChanged {
    pub fn key(&self) -> String {
        format!("DidOwnerChanged-{}", self.owner.as_ref())
    }
}

impl DidEvents {
    pub fn previous_change(&self) -> Block {
        match self {
            DidEvents::AttributeChangedEvent(event) => event.previous_change.clone(),
            DidEvents::DelegateChanged(event) => event.previous_change.clone(),
            DidEvents::OwnerChanged(event) => event.previous_change.clone(),
        }
    }
}
