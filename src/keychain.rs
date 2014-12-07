use std::io::File;
use serialize::json;
use serialize::base64::FromBase64;

use serialize::{Decoder, Decodable};

use rust_crypto::mac::Mac;
use rust_crypto::hmac::Hmac;
use rust_crypto::sha2::Sha256;
use rust_crypto::pbkdf2::pbkdf2;
use rust_crypto::aes::{cbc_decryptor, KeySize};
use rust_crypto::blockmodes::NoPadding;
use rust_crypto::symmetriccipher::Decryptor;
use rust_crypto::buffer::{ReadBuffer, RefReadBuffer,RefWriteBuffer};


struct SaltedString {
    salt: Vec<u8>,
    data: Vec<u8>
}

impl<E, D: Decoder<E>> Decodable<D, E> for SaltedString {
    fn decode(d: &mut D) -> Result<SaltedString, E> {
        let bytes = try!(d.read_str());


        let data = bytes.slice_to(bytes.len() - 1);
        let decoded = data.from_base64();

        if !decoded.is_ok() {
            return Err(d.error("could not decode base64 data"));
        }

        let decoded_string = decoded.unwrap();

        let prefix = decoded_string.slice_to(8);

        if prefix == "Salted__".as_bytes() {
            let mut salt: Vec<u8> = Vec::new();
            let mut data: Vec<u8> = Vec::new();

            salt.push_all(decoded_string[8..16]);
            data.push_all(decoded_string[16..]);

            return Ok(SaltedString {
                salt: salt,
                data: data
            });
        }

        let mut data: Vec<u8> = Vec::new();
        data.push_all(decoded_string.as_slice());

        return Ok(SaltedString {
            salt: Vec::from_elem(16, 0),
            data: data
        });
    }
}

#[deriving(Decodable)]
pub struct EncryptionKeyList {
    list: Vec<EncryptionKey>
}

#[deriving(Decodable)]
pub struct EncryptionKey {
    iterations: u32,
    level: String,
    identifier: String,
    validation: SaltedString,
    data: SaltedString
}

impl EncryptionKey {
    pub fn decrypt(&self, data: Vec<u8>) -> Vec<u8> {

    }

    pub fn encrypt(&self, data: Vec<u8>) -> Vec<u8> {

    }

    pub fn unlock<M: Mac>(&self, mac: &mut M, password: &str) -> Vec<u8> {
        let ref salt = self.data.salt;
        let mut buffer =  [0, ..32];
        pbkdf2(mac, salt.as_slice(), self.iterations, &mut buffer);

        println!("PBKDF2: {}", buffer);

        // create aes encryptor
        let mut enc = cbc_decryptor(KeySize::KeySize128, buffer[0..16], buffer[16..32], NoPadding);
        let mut data = RefReadBuffer::new(self.data.data.as_slice());
        let mut key_buffer = Vec::from_elem(data.capacity(), 0);
        let mut output = RefWriteBuffer::new(key_buffer.as_mut_slice());
        let result = enc.decrypt(&mut data, &mut output, true);

        return key_buffer;
    }
}

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

    pub fn open(&self, password: &str) -> bool {
        let mut mac = Hmac::new(Sha256::new(), password.as_bytes());

        for key in self.keys.iter() {

        }

        return true;
    }
}

#[cfg(test)]
mod unittest {

    use serialize::json;
    use keychain::{EncryptionKey, EncryptionKeyList};
    use test::Bencher;

    #[bench]
    fn bench_decodes_encryption_key(b: &mut Bencher) {

        let encoded = r#"{
            "iterations": 10000,
            "level": "SL3",
            "identifier": "368EF53CA90A482391DF5D87A52DD877",
            "data": "I8m/KjE9P9MfpKJU35N2IDaP\u0000",
            "validation": "3YSix7TStgYYU1h\u0000"
        }"#;

        b.iter(|| {
            let decoded: EncryptionKey = json::decode(encoded.as_slice()).unwrap();
        });
    }

    #[test]
    fn decodes_encryption_key() {

        let encoded = r#"{
            "iterations": 10000,
            "level": "SL3",
            "identifier": "368EF53CA90A482391DF5D87A52DD877",
            "data": "I8m/KjE9P9MfpKJU35N2IDaP\u0000",
            "validation": "3YSix7TStgYYU1h\u0000"
        }"#;

        let decoded: EncryptionKey = json::decode(encoded.as_slice()).unwrap();

        assert!(decoded.iterations == 10000);
        assert!(decoded.level.as_slice() == "SL3");
        assert!(decoded.identifier.as_slice() == "368EF53CA90A482391DF5D87A52DD877");
        //assert!(decoded.data.as_slice() == "I8m/KjE9P9MfpKJU35N2IDaP\0");
        //assert!(decoded.validation.as_slice() == "3YSix7TStgYYU1h\0");
    }

    #[test]
    fn decodes_encryption_key_list() {

        let encoded = r#"{
            "list": [{
                "iterations": 10000,
                "level": "SL3",
                "identifier": "368EF53CA90A482391DF5D87A52DD877",
                "data": "I8m/KjE9P9MfpKJU35N2IDaP\u0000",
                "validation": "3YSix7TStgYYU1h\u0000"
            }, {
                "iterations": 42,
                "level": "SL5",
                "identifier": "368EF53CA90391DF5D87A52DD877",
                "data": "I8m/KjE9P9Mf35N2IDaP\u0000",
                "validation": "3YSix7TYYU1h\u0000"
            }]
        }"#;

        let decoded: EncryptionKeyList = json::decode(encoded.as_slice()).unwrap();

        assert!(decoded.list[0].iterations == 10000);
        assert!(decoded.list[0].level.as_slice() == "SL3");
        assert!(decoded.list[0].identifier.as_slice() == "368EF53CA90A482391DF5D87A52DD877");
        //assert!(decoded.list[0].data.as_slice() == "I8m/KjE9P9MfpKJU35N2IDaP\0");
        //assert!(decoded.list[0].validation.as_slice() == "3YSix7TStgYYU1h\0");

        assert!(decoded.list[1].iterations == 42);
        assert!(decoded.list[1].level.as_slice() == "SL5");
        assert!(decoded.list[1].identifier.as_slice() == "368EF53CA90391DF5D87A52DD877");
        //assert!(decoded.list[1].data.as_slice() == "I8m/KjE9P9Mf35N2IDaP\0");
        //assert!(decoded.list[1].validation.as_slice() == "3YSix7TYYU1h\0");
    }
}
