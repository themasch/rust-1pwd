use std::io::File;
use serialize::json;

pub use encryption_key::{EncryptionKey, EncryptionKeyList};

use rust_crypto::hmac::Hmac;
use rust_crypto::sha2::Sha256;
use rust_crypto::digest::Digest;

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
        let mut mac = Hmac::new(Sha256::new(), password.as_bytes());

        for key in self.keys.iter_mut() {
            key.unlock(&mut mac);
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
        kc.open("password");
    }
}
