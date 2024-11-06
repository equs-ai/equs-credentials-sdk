#![deny(clippy::all)]
pub mod did;
pub mod http;
#[cfg(any(test, feature = "in-memory"))]
pub mod inmem;
pub mod kms;
pub mod nonce;
pub(crate) mod utils;
pub mod vault;
pub mod vc;

pub use utils::{enable_logs, resolve_metadata};
