#![allow(dead_code)]
#![allow(unused_variables)]

// external
pub mod crypto;
pub mod kms;
pub mod vault;
pub mod storage;

// core
mod vc;
mod did;
pub(crate) mod utils;
pub(crate) mod inmem;

// TODO: move to a separate crate
#[cfg(feature = "askar")]
pub mod askar;

