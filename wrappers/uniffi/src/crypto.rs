use crate::common::{Duration, OffsetDateTime};

pub type KeyMetadata = agent_sdk::vc::core::KeyMetadata;
pub type Nonce = agent_sdk::nonce::Nonce;
pub type NonceData = agent_sdk::nonce::NonceData;

uniffi::custom_type!(Nonce, String, {
    remote,
    lower: |nonce| nonce.secret().to_string(),
    try_lift: |nonce| Ok(Nonce::from_secret(nonce)),
});

#[uniffi::remote(Record)]
pub struct KeyMetadata {
    pub did_url: String,
    pub kid: String,
}

#[uniffi::remote(Record)]
pub struct NonceData {
    pub value: Nonce,
    pub created: OffsetDateTime,
    pub expires_in: Option<Duration>,
}
