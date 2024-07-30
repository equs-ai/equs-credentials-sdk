use crate::core_::{pop, vc};

pub type Proof = vc::JWTRaw;

impl pop::Proof for Proof {
    fn parse(str: &str) -> pop::Result<Self> {
        Ok(str.to_owned())
    }
}