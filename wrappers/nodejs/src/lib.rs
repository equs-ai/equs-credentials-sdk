#![deny(clippy::all)]
#[cfg(any(test, feature = "in-memory"))]
pub mod inmem;
pub mod kms;
pub mod nonce;
pub(crate) mod utils;
pub mod vault;
pub mod vc;
pub use utils::{create_did_and_key_metadata, enable_logs, resolve_metadata};
