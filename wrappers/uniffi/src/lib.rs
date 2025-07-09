#![allow(dead_code)]
#![allow(clippy::new_without_default)]

mod common;
mod crypto;
pub mod did;
pub mod http;
pub mod inmem;
pub mod key_handle;
pub mod kms;
mod nonce;
mod utils;
mod vault;
pub mod vc;

uniffi::setup_scaffolding!();
