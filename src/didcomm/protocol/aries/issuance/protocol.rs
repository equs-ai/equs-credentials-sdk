use async_trait::async_trait;

use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::issuance::holder::IssuanceHolder;
use crate::didcomm::protocol::aries::issuance::holder::states::IssuanceHolderState;
use crate::didcomm::protocol::aries::issuance::issuer::Issuer;
use crate::didcomm::protocol::aries::issuance::issuer::states::IssuerState;
use crate::didcomm::protocol::aries::issuance::{PROTOCOL_NAME, PROTOCOL_VERSION};
use crate::kms::{KeyHandle, Kms};
use crate::storage::Storage;
use crate::vault::Vault;

pub struct IssuanceProtocol {
    handlers: Vec<Box<dyn MessageHandler>>,
}

impl IssuanceProtocol {
    pub fn new_with_issuer<KMS, KH, C, S>(issuer: Issuer<KMS, KH, C, S>) -> Self
    where
        KMS: Kms<KH> + Clone + 'static,
        KH: KeyHandle + 'static,
        C: ConnectionService + Clone + 'static,
        S: Storage<String, IssuerState> + Clone + 'static,
    {
        IssuanceProtocol {
            handlers: vec![Box::new(issuer)],
        }
    }

    pub fn new_with_holder<KMS, KH, S, C, V>(holder: IssuanceHolder<KMS, KH, S, C, V>) -> Self
    where
        KMS: Kms<KH> + Clone + 'static,
        KH: KeyHandle + 'static,
        S: Storage<String, IssuanceHolderState> + Clone + 'static,
        C: ConnectionService + Clone + 'static,
        V: Vault + Clone + 'static,
    {
        IssuanceProtocol {
            handlers: vec![Box::new(holder)],
        }
    }
}

#[async_trait]
impl Protocol for IssuanceProtocol {
    fn protocol_name(&self) -> &'static str {
        PROTOCOL_NAME
    }

    fn protocol_version(&self) -> &'static str {
        PROTOCOL_VERSION
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        self.handlers.iter().map(AsRef::as_ref).collect()
    }
}
