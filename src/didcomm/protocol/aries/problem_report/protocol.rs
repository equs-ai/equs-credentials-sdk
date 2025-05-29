use crate::didcomm::core::protocol::message_handler::MessageHandler;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::protocol::aries::problem_report::{PROTOCOL_NAME, PROTOCOL_VERSION};

pub struct ProblemReportProtocol {
    handler: Box<dyn MessageHandler>,
}

impl ProblemReportProtocol {
    pub fn new(handler: Box<dyn MessageHandler>) -> Self {
        ProblemReportProtocol { handler }
    }
}

impl Protocol for ProblemReportProtocol {
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
