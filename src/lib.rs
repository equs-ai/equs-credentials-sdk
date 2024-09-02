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
// TODO: expose only http client trait here
pub mod utils;
// TODO: make private after moving the oid4vc
pub mod inmem;

// TODO: move to a separate crate
#[cfg(feature = "askar")]
pub mod askar;

