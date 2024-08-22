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
pub mod utils;
pub mod inmem;

// TODO: move to a separate crate
#[cfg(feature = "askar")]
pub mod askar;

