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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn addr(hex_suffix: &str) -> Address {
        Address::from(format!("0x{hex_suffix}").as_str())
    }

    fn attr_event() -> DidAttributeChanged {
        DidAttributeChanged {
            identity: addr("1111111111111111111111111111111111111111"),
            name: "did/pub/Secp256k1/veriKey/hex".to_string(),
            value: vec![1, 2, 3],
            valid_to: 100,
            previous_change: Block::from(42),
        }
    }

    fn delegate_event() -> DidDelegateChanged {
        DidDelegateChanged {
            identity: addr("1111111111111111111111111111111111111111"),
            delegate: addr("2222222222222222222222222222222222222222"),
            delegate_type: vec![0xAA, 0xBB],
            valid_to: 200,
            previous_change: Block::from(7),
        }
    }

    fn owner_event() -> DidOwnerChanged {
        DidOwnerChanged {
            identity: addr("1111111111111111111111111111111111111111"),
            owner: addr("3333333333333333333333333333333333333333"),
            previous_change: Block::from(13),
        }
    }

    #[test]
    fn did_attribute_changed_key_formats_name_and_value_debug() {
        let event = attr_event();

        assert_eq!(
            event.key(),
            "DidDocAttribute-did/pub/Secp256k1/veriKey/hex-[1, 2, 3]"
        );
    }

    #[test]
    fn did_delegate_changed_key_formats_delegate_type_and_address() {
        let event = delegate_event();

        assert_eq!(
            event.key(),
            "DelegateChanged-[170, 187]-0x2222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn did_owner_changed_key_formats_owner_address() {
        let event = owner_event();

        assert_eq!(
            event.key(),
            "DidOwnerChanged-0x3333333333333333333333333333333333333333"
        );
    }

    #[rstest]
    #[case::attribute(DidEvents::AttributeChangedEvent(attr_event()), 42)]
    #[case::delegate(DidEvents::DelegateChanged(delegate_event()), 7)]
    #[case::owner(DidEvents::OwnerChanged(owner_event()), 13)]
    fn previous_change_extracts_block_from_each_variant(
        #[case] event: DidEvents,
        #[case] expected: u64,
    ) {
        assert_eq!(event.previous_change().value(), expected);
    }
}
