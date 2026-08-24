#![type_length_limit = "20000"]
#![recursion_limit = "256"]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::blocks_in_conditions)]
#![allow(clippy::new_without_default)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::assigning_clones)]
// #![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

// external
pub mod crypto;
pub mod http;
pub mod jwe;
pub mod kms;
pub mod storage;
pub mod vault;

// core
pub mod did;
#[cfg(not(target_arch = "wasm32"))]
pub mod didcomm;
#[cfg(any(test, feature = "in-memory"))]
pub mod inmem;
pub mod nonce;
pub mod reqwest;
mod utils;
pub mod vc;

pub use time::{Duration, OffsetDateTime};
pub use utils::chrono_time_mapping;
