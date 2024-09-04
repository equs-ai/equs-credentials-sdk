#![allow(dead_code)]
#![allow(unused_variables)]

// external
pub mod crypto;
pub mod kms;
pub mod vault;
pub mod storage;

// core
pub mod vc;
pub mod did;
mod utils;
pub mod http;
// TODO: make private after moving the oid4vc
pub mod inmem;
pub mod reqwest;

// TODO: move to a separate crate
#[cfg(feature = "askar")]
pub mod askar;
