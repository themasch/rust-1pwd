use std::io::File;
use serialize::json;

#[deriving(Decodable, Encodable)]
pub struct EncryptionKeyList {
    list: Vec<EncryptionKey>
}

#[deriving(Decodable, Encodable)]
pub struct EncryptionKey {
    iterations: u32,
    level: String,
    identifier: String,
    validation: String,
    data: String
}

pub struct Keychain {
    pub path: Path,
    pub keys: Vec<EncryptionKey>
}

impl Keychain {
    pub fn from_file(path: &Path) -> Option<Keychain> {    // TODO: switch to result here & put cool error messages
        let key_path = path.join("data/default/encryptionKeys.js");
        let contents = File::open(&key_path).read_to_string().unwrap();

        let key_list: EncryptionKeyList = json::decode(contents.as_slice()).unwrap();

        return Some(Keychain {
            path: path.clone(),
            keys: key_list.list
        });
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
        assert!(decoded.data.as_slice() == "I8m/KjE9P9MfpKJU35N2IDaP\0");
        assert!(decoded.validation.as_slice() == "3YSix7TStgYYU1h\0");
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
        assert!(decoded.list[0].data.as_slice() == "I8m/KjE9P9MfpKJU35N2IDaP\0");
        assert!(decoded.list[0].validation.as_slice() == "3YSix7TStgYYU1h\0");

        assert!(decoded.list[1].iterations == 42);
        assert!(decoded.list[1].level.as_slice() == "SL5");
        assert!(decoded.list[1].identifier.as_slice() == "368EF53CA90391DF5D87A52DD877");
        assert!(decoded.list[1].data.as_slice() == "I8m/KjE9P9Mf35N2IDaP\0");
        assert!(decoded.list[1].validation.as_slice() == "3YSix7TYYU1h\0");
    }
}
