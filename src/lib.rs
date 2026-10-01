#![doc = include_str!("../README.md")]

pub mod cred;
pub use cred::CredPersist;
pub mod store;
pub use store::Store;
pub mod hello_store;
pub use hello_store::HelloStore;
pub mod hello;
mod hello_crypto;
mod hello_mutex;
mod hello_native;
#[cfg(test)]
mod hello_tests;
#[cfg(test)]
mod tests;
mod utils;
