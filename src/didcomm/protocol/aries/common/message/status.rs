use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::didcomm::protocol::aries::problem_report::message::ProblemReport;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Status {
    Undefined,
    Success,
    Failed(ProblemReport),
    Rejected(Option<ProblemReport>),
}

impl Status {
    pub fn code(&self) -> u32 {
        match self {
            Status::Undefined => 0,
            Status::Success => 1,
            Status::Failed(err) => {
                error!("Process Failed: {:?}", err);
                2
            }
            Status::Rejected(rep) => {
                info!("Process Rejected: {:?}", rep);
                3
            }
        }
    }
}
