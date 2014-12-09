use std::io::File;
use serialize::json;

pub use encryption_key::{EncryptionKey, EncryptionKeyList};

pub struct Keychain {
    pub path: Path,
    pub keys: Vec<EncryptionKey>
}

impl Keychain {

    /// `from_file` creates a new Keychain instance from a given path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the agilekeychain folder.
    ///
    pub fn from_file(path: &Path) -> Option<Keychain> {    // TODO: switch to result here & put cool error messages
        let key_path = path.join("data/default/encryptionKeys.js");
        let contents = File::open(&key_path).read_to_string().unwrap();

        let key_list: EncryptionKeyList = json::decode(contents.as_slice()).unwrap();

        return Some(Keychain {
            path: path.clone(),
            keys: key_list.list
        });
    }

    pub fn open(&mut self, password: &str) -> bool {

        for key in self.keys.iter_mut() {
            if !key.unlock(password.as_bytes()) {
                return false;
            }
        }

        return true;
    }
}


#[cfg(test)]
mod unittest {

    use keychain::Keychain;

    #[test]
    fn load_keychain() {
        let kc_path = Path::new("./testdata/1Password.agilekeychain");
        let kc = Keychain::from_file(&kc_path).unwrap();

        assert!(kc.path == kc_path);
    }

    #[test]
    fn unlock_keychain() {
        let kc_path = Path::new("./testdata/1Password.agilekeychain");
        let mut kc = Keychain::from_file(&kc_path).unwrap();
        assert!(kc.open("password"));
    }

        #[test]
    fn fail_to_unlock_keychain() {
        let kc_path = Path::new("./testdata/1Password.agilekeychain");
        let mut kc = Keychain::from_file(&kc_path).unwrap();
        assert!(!kc.open("not_the_password"));
    }
}
