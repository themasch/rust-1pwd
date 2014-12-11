use std::io::File;
use serialize::json;
use serialize::json::DecoderError;
use std::error::Error;

pub use encryption_key::{EncryptionKey, EncryptionKeyList};
pub use items::ContentItem;

pub struct Keychain {
    pub path: Path,
    pub keys: Vec<EncryptionKey>,
    pub items: Vec<ContentItem>
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

        let item_path = path.join("data/default/contents.js");
        let item_contents = File::open(&item_path).read_to_string().unwrap();

        let key_list: EncryptionKeyList = json::decode(contents.as_slice()).unwrap();
        let item_list: Vec<ContentItem> = json::decode(item_contents.as_slice()).unwrap();

        return Some(Keychain {
            path: path.clone(),
            keys: key_list.list,
            items: item_list
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
    fn loads_content_keychain() {
        let kc_path = Path::new("./testdata/1Password.agilekeychain");
        let kc = Keychain::from_file(&kc_path).unwrap();

        assert!(kc.items[0].name == "Example Login");
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
