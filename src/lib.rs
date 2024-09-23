#![allow(dead_code)]
#![allow(unused_variables)]
// Below rule has bug: https://github.com/rust-lang/rust-clippy/issues/12281
#![allow(clippy::blocks_in_conditions)]
#![allow(clippy::new_without_default)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::assigning_clones)]

// external
pub mod crypto;
pub mod http;
pub mod kms;
pub mod storage;
pub mod vault;

// core
pub mod did;
mod utils;
pub mod vc;

#[cfg(any(test, feature = "in-memory"))]
pub mod inmem;
pub mod reqwest;
