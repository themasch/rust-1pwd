#![feature(slicing_syntax)]

extern crate serialize;
extern crate test;
extern crate "rust-crypto" as rust_crypto;

pub use keychain::Keychain;

mod keychain;
