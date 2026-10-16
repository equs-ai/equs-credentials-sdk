use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::protocol::aries::empty::{PROTOCOL_NAME, PROTOCOL_VERSION};

pub struct EmptyProtocol {
    handler: Box<dyn MessageHandler>,
}

impl EmptyProtocol {
    pub fn new(handler: Box<dyn MessageHandler>) -> Self {
        EmptyProtocol { handler }
    }
}

impl Protocol for EmptyProtocol {
    fn protocol_name(&self) -> &'static str {
        PROTOCOL_NAME
    }

    fn protocol_version(&self) -> &'static str {
        PROTOCOL_VERSION
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        vec![self.handler.as_ref()]
    }
}
