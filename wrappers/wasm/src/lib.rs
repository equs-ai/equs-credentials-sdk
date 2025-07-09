pub mod crypto;
pub mod did;
mod http;
pub mod inmem;
pub mod kms;
mod nonce;
pub mod utils;
pub mod vault;
pub mod vc;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
