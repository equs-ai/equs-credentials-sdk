use crate::core_::pop;

pub type Proof = ssi::vc::Presentation;

impl pop::Proof for Proof {
    fn parse(str: &str) -> pop::Result<Self> {
        Ok(ssi::vc::Presentation::from_json(str)?)
    }
}