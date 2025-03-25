mod common;
mod did;
mod utils;
pub mod vc;

pub use did::*;

uniffi::include_scaffolding!("asdk");
