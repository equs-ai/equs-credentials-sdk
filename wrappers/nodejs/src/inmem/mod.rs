use crate::kms::NativeKms;
use crate::nonce::NativeNonceGenerator;
use crate::vault::NativeVault;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::inmem::vault::InMemVault;
use napi_derive::napi;

#[napi]
pub fn in_mem_kms() -> NativeKms {
    let local_kms = LocalKms::new();
    let mut native_kms = NativeKms::from(local_kms.clone());
    native_kms.set_ecdh1pu_derivation(local_kms.clone());
    native_kms.set_ecdhes_derivation(local_kms);

    native_kms
}

#[napi]
pub fn in_mem_vault() -> NativeVault {
    NativeVault::from(InMemVault::new())
}

#[napi]
pub fn local_nonce_generator() -> NativeNonceGenerator {
    NativeNonceGenerator::from(LocalNonceGenerator::default())
}
