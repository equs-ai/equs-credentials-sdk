use crate::core_::pop;

pub type Proof = ssi::vc::Presentation;

impl pop::Proof for Proof {}

pub trait ProofOfPossessionAPI: pop::ProofOfPossession<Proof> {}