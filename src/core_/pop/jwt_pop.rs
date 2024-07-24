use crate::core_::{pop, vc};

pub type Proof = vc::JWTRaw;

impl pop::Proof for Proof {}