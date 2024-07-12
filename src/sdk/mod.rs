use crate::exchange;

pub struct ASDK {}

// Error handling

pub enum SDKError {}

// Configs
pub struct Oid4vcIssuerConfig;

impl ASDK {
    pub fn oid4vc_issuer(config: &Oid4vcIssuerConfig) -> impl exchange::oid4vc::Issuer {}
}