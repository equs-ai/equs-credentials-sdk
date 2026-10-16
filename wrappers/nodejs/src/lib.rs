#![deny(clippy::all)]
pub mod did;
pub mod didcomm;
mod error;
pub mod http;
#[cfg(any(test, feature = "in-memory"))]
pub mod inmem;
pub mod kms;
mod nonce;
#[cfg(feature = "test-fixtures")]
pub mod test_fixtures;
pub(crate) mod utils;
pub mod vault;
pub mod vc;

pub use utils::{enable_logs, parse_claims, resolve_metadata};
