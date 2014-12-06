extern crate serialize;
extern crate test;

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
}
