use agent_sdk::inmem::kms::LocalKms;

#[derive(uniffi::Object)]
pub struct InMemKms(LocalKms);

#[uniffi::export()]
impl InMemKms {
    #[uniffi::constructor]
    pub fn new() -> Self {
        InMemKms(LocalKms::new())
    }
}

impl InMemKms {
    pub fn inner(&self) -> LocalKms {
        self.0.clone()
    }
}
