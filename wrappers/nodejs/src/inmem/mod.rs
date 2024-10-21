use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::inmem::vault::InMemVault;
use napi_derive::napi;

use crate::kms::NativeKms;
use crate::nonce::NativeNonceGenerator;
use crate::vault::NativeVault;

#[napi]
pub fn in_mem_kms() -> NativeKms {
    NativeKms::from(LocalKms::new())
}

#[napi]
pub fn in_mem_vault() -> NativeVault {
    NativeVault::from(InMemVault::new())
}

#[napi]
pub fn local_nonce_generator() -> NativeNonceGenerator {
    NativeNonceGenerator::from(LocalNonceGenerator::default())
}
