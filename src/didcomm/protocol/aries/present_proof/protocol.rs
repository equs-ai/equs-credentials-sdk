use async_trait::async_trait;

use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::present_proof::holder::PresentationHolder;
use crate::didcomm::protocol::aries::present_proof::holder::states::PresentationHolderState;
use crate::didcomm::protocol::aries::present_proof::verifier::Verifier;
use crate::didcomm::protocol::aries::present_proof::verifier::states::VerifierState;
use crate::didcomm::protocol::aries::present_proof::{PROTOCOL_NAME, PROTOCOL_VERSION};
use crate::kms::{KeyHandle, Kms};
use crate::storage::Storage;
use crate::vault::Vault;

pub struct PresentationProtocol {
    handlers: Vec<Box<dyn MessageHandler>>,
}

impl PresentationProtocol {
    pub fn new_with_verifier<KMS, KH, C, S>(verifier: Verifier<KMS, KH, C, S>) -> Self
    where
        KMS: Kms<KH> + Clone + 'static,
        KH: KeyHandle + 'static,
        C: ConnectionService + Clone + 'static,
        S: Storage<String, VerifierState> + Clone + 'static,
    {
        PresentationProtocol {
            handlers: vec![Box::new(verifier)],
        }
    }

    pub fn new_with_holder<KMS, KH, S, C, V>(holder: PresentationHolder<KMS, KH, S, C, V>) -> Self
    where
        KMS: Kms<KH> + Clone + 'static,
        KH: KeyHandle + 'static,
        S: Storage<String, PresentationHolderState> + Clone + 'static,
        C: ConnectionService + Clone + 'static,
        V: Vault + Clone + 'static,
    {
        PresentationProtocol {
            handlers: vec![Box::new(holder)],
        }
    }
}

#[async_trait]
impl Protocol for PresentationProtocol {
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
