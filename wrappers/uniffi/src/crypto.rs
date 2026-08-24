pub type KeyMetadata = equs_sdk::vc::core::KeyMetadata;
pub type Nonce = equs_sdk::nonce::Nonce;

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
