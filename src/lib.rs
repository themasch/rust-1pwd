#![feature(slicing_syntax)]

extern crate serialize;
extern crate test;
extern crate "rust-crypto" as rust_crypto;

pub use keychain::Keychain;

mod keychain;


#[cfg(test)]

mod unittest {

    use keychain::Keychain;

    #[test]
    fn load_keychain() {
        let kc_path = Path::new("./keys.agilekeychain");
        let kc = Keychain::from_file(&kc_path).unwrap();

        assert!(kc.path == kc_path);
    }

    #[test]
    fn unlock_keychain() {
        let kc_path = Path::new("./keys.agilekeychain");
        let kc = Keychain::from_file(&kc_path).unwrap();
        kc.open("asdf");
    }
}
