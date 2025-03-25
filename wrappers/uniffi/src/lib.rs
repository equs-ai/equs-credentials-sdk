#![allow(dead_code)]
#![allow(clippy::new_without_default)]

mod common;
mod crypto;
pub mod did;
pub mod inmem;
mod utils;
pub mod vc;

uniffi::setup_scaffolding!();
