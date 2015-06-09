#![feature(test,convert,collections)]

extern crate test;
extern crate openssl;
extern crate rustc_serialize;

pub use keychain::Keychain;

mod cryptlib;
mod encryption_key;
mod keychain;
mod items;
