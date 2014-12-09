use serialize::base64::FromBase64;

use serialize::{Decoder, Decodable};

use cryptlib::decrypt_aes;

use rust_crypto::mac::Mac;
use rust_crypto::pbkdf2::pbkdf2;
use rust_crypto::md5::Md5;
use rust_crypto::digest::Digest;
use rust_crypto::hmac::Hmac;
use rust_crypto::sha1::Sha1;

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
            let salt: Vec<u8> = decoded_string[8..16].to_vec();
            let data: Vec<u8> = decoded_string[16..].to_vec();

            return Ok(SaltedString {
                salt: salt,
                data: data
            });
        }

        let data: Vec<u8> =decoded_string.to_vec();

        return Ok(SaltedString {
            salt: Vec::from_elem(16, 0),
            data: data
        });
    }
}

#[deriving(Decodable)]
pub struct EncryptionKeyList {
    pub list: Vec<EncryptionKey>
}

#[deriving(Decodable)]
pub struct EncryptionKey {
    iterations: u32,
    level: String,
    identifier: String,
    validation: SaltedString,
    data: SaltedString,

    decrypted_key: Option<Vec<u8>>
}

struct KeyIV {
    key: [u8, ..16],
    iv: [u8, ..16]
}

impl EncryptionKey {

    pub fn derive_md5(&self, password: &[u8], salt: &[u8]) -> KeyIV {
        // init IV with md5
        let mut input_vec = password.to_vec();
        let mut key_arr = [0u8, ..16];
        let mut iv_arr  = [0u8, ..16];
        input_vec.push_all(salt);

        let mut hash = Md5::new();
        hash.input(input_vec.as_slice());
        hash.result(&mut key_arr);


        hash = Md5::new();
        hash.input(&key_arr);
        hash.input(input_vec.as_slice());
        hash.result(&mut iv_arr);

        let result = KeyIV {
            key: key_arr,
            iv: iv_arr
        };

        return result;
        //copy_memory(output, res.as_bytes())
    }

    pub fn derive_pbkdf2(&self, key: &[u8], salt: &[u8], output: &mut [u8]) {
        let mut mac = Hmac::new(Sha1::new(), key);
        pbkdf2(&mut mac, salt, self.iterations, output);
    }

    pub fn decrypt(&self, data: &SaltedString) -> Vec<u8> {
        let key = self.decrypted_key.as_ref().unwrap();

        let key_iv = self.derive_md5(
            key.as_slice(),
            data.salt.as_slice()
        );

        decrypt_aes(&key_iv.key, &key_iv.iv, data.data.as_slice())
    }

    /*pub fn encrypt(&self, data: Vec<u8>) -> Vec<u8> {
        return data;
    }*/

    pub fn unlock(&mut self, password: &[u8]) -> bool {
        let salt = self.data.salt.as_slice();
        let mut buffer =  [0u8, ..32];
        self.derive_pbkdf2(password, salt, &mut buffer);

        let key = decrypt_aes(
            buffer[0..16],
            buffer[16..32],
            self.data.data.as_slice()
        );

        let key_vec = key.to_vec();
        let key_copy = key_vec.as_slice();

        self.decrypted_key = Some(key);

        let ref valid = self.validation;
        let decrypted_validation = self.decrypt(valid);

        decrypted_validation == key_copy
    }
}

#[cfg(test)]
mod unittest {

    use serialize::json;
    use keychain::{EncryptionKey, EncryptionKeyList};

    #[test]
    fn decodes_encryption_key() {

        let encoded = r#"{
            "iterations": 10000,
            "level": "SL3",
            "identifier": "408C2E2D6A8B480893068AC602FA6D7B",
            "data": "U2FsdGVkX1+DH6j2TyYeRIyn81Cv1IStle5B+xOklItRF52HTKfPoLnBHuAhu7teGmf/q3y2aSH/OJOioi/VxkrYMBXJIOGovNS6xvsO/1XJIIRmv8QcxGaoKbZXr99EgB414mvJOG0+Wi3wQ6OXHQG+vy0zadyE32Q9XtkfgNs/qhhgFvBxONKXK3M5lo3i5MsUvBFVTa3ghQw2+cqUZ6IJbCy/2w8+AQlRJu070GVDC0KXIcge5vYgxYwkgL5J++HM5D40oSDnnk42fcSF4XyvvW3WswbdLbgwLO+g18oTavi8qvFCZ99BgSkcI+ZbtvsuXefQH84L+hizesVKCSsVrWu5zxMZb0C1MEOQrlzePwB8EJ9huoUbS/YKqb4BhR0xE3QgAduIIpeHhhHCJlbGLYoUUbBzWlCRQNG79iKCzES4w/RTttnHOfitW5JQPKTm+/S7OvmEoQI0y8cclHnCJvp5wxbVP1J2ISEFRq6kanZva/4raAN66IfyQyPYqk/R1HsOByutanJJ5qSnhNFNaZsI9h9Ee899FBntHdMFyIy+XAsCdqfvk0fM6vBex1SAZQYISonhI5pB/WbOxTlGLg85eiJ5BjikskxwUzmJV2NQBc9gIV1QSegZtIA7v3q83vnuwDXJQliMCTEmpdTG9UQ/gm8yzJWkUBpb\u0000",
            "validation": "U2FsdGVkX1+NtjhEJU9qkGUxkqUjhSz8FZVXDsMMwlBwwzhOYHvsAxMzjBBEYYk4axYE6GLI44lZsDHWo7ltacWZcLnJETs9e3kmq6NTBYbwrwV6a9eH/lXNmL1nVhdt4TplmnJc7bF/mwZquZ1HTMbX8xTK3/LF3STA8xLKjDrjO8DQBitQfRtr43mN5eSB0Vn9skfGbENfzjxj0hpbqxKhEvC4ijFf8jXvyrjt9hr2HX1C4aJXJHAfkvrp5DMzzG2gMGzo4wLPqH5PrApIoZQD9ORRmmvKkoJ868yn6QKaQhynOP0Jt63sgvw0d0NmNztXClFKmsOYe3he+UbIQnPNCWEyK6/+gU+Rflb71tdpYsUFMeSH1AlTvyBW/jxqAH44/jzNIFILqPvd3dHqgo/I1OJzkn0ShN8gLZ2mYs9rMaCiGggiUd8GJtOeke90jFFCPqqb3D82uzBnbxJ49iziMHC19JFmSqi27leXR0vqr+2wX88oROAb54phSNs3islM3JxxnNqwj8xptOuzRTp6RaGt+9PKZh4vFDDehlM6wc4UwQrf92lSKFeT7Hha5KXiqb356Z4aAjFykvkMzgLaAICQOTNK5CtsOSwGtfl64LzOmN7Tk7LR2U70eUa0h2KCoxYhe+AaIQPEUUGKFMQ4lGsqZ10XAhRyefiFEUrMsORdFf5qbaKsLGudzNaU/t5megiRUN7X4vo3YUz/YLonHc2q2FO3n2RuiUY+L+qg5mI+lHwMFQs+1OyrUWvimp93XhmIc0PoSRrU95JGxY5CSxUkvso7aBN4R1tPqKyf6HZuAu80RUvJj6Lk5ylYD5z4oSrQ79wRhjIVW06VzZUSGUVS1+rTcnNDTpPfDtC2alr10fkljSYDDqypwFW4+J55+k70CRjLl39Ikt5M1rrT7YdrgzBF4a4XS0w9oKJPGI741Pr/EaupuKh49QE+FHnRed1+upRW3FtF+lI7P6+GnDjxWhZZFzX16OJlCRpKNc3+Aa4fEyv++k4whhOfwssIqeefy37Oe1fgjX8AgGhKUswuyCME8ctP/jpvqliKvCPHPzyHohquL3yn9bkZJsAAGP7bYok9Na0AcxErEVdmGGEadLDiXGVgILvXk5AxGvWVLp4dt5mctajx0mHClRz7XSF4YU0zftcZ84OCIbagbvH6TJy0iQv9GVTNGBE9zTH2GhDdHv/UFzXPN3f8rDGHZdBL1o9c5mEu3AoGi4pDokH0M1+mqyERXJhgkszKhFN+PMZfZT/92azIZNR7+GUCW9D1MI52wx00OuQCKskD8FhmMH6n6GpndP84YvWardOz7OTErxfgYpnI3g0mpy7UD5RuTIXSgFUAQDv8TC/EnuPFQBfMPlslkPCsSFR2mRemoGmxlQ7IARndAZos\u0000"
        }"#;

        let decoded: EncryptionKey = json::decode(encoded.as_slice()).unwrap();

        let salt: Vec<u8> = vec![ 0x83, 0x1f, 0xa8, 0xf6, 0x4f, 0x26, 0x1e, 0x44 ];
        assert!(decoded.iterations == 10000);
        assert!(decoded.level.as_slice() == "SL3");
        assert!(decoded.identifier.as_slice() == "408C2E2D6A8B480893068AC602FA6D7B");
        assert!(decoded.data.salt == salt);

    }

    #[test]
    fn decodes_encryption_key_list() {

        let encoded = r#"{
            "list": [{
                "iterations": 10000,
                "level": "SL3",
                "identifier": "408C2E2D6A8B480893068AC602FA6D7B",
                "data": "U2FsdGVkX1+DH6j2TyYeRIyn81Cv1IStle5B+xOklItRF52HTKfPoLnBHuAhu7teGmf/q3y2aSH/OJOioi/VxkrYMBXJIOGovNS6xvsO/1XJIIRmv8QcxGaoKbZXr99EgB414mvJOG0+Wi3wQ6OXHQG+vy0zadyE32Q9XtkfgNs/qhhgFvBxONKXK3M5lo3i5MsUvBFVTa3ghQw2+cqUZ6IJbCy/2w8+AQlRJu070GVDC0KXIcge5vYgxYwkgL5J++HM5D40oSDnnk42fcSF4XyvvW3WswbdLbgwLO+g18oTavi8qvFCZ99BgSkcI+ZbtvsuXefQH84L+hizesVKCSsVrWu5zxMZb0C1MEOQrlzePwB8EJ9huoUbS/YKqb4BhR0xE3QgAduIIpeHhhHCJlbGLYoUUbBzWlCRQNG79iKCzES4w/RTttnHOfitW5JQPKTm+/S7OvmEoQI0y8cclHnCJvp5wxbVP1J2ISEFRq6kanZva/4raAN66IfyQyPYqk/R1HsOByutanJJ5qSnhNFNaZsI9h9Ee899FBntHdMFyIy+XAsCdqfvk0fM6vBex1SAZQYISonhI5pB/WbOxTlGLg85eiJ5BjikskxwUzmJV2NQBc9gIV1QSegZtIA7v3q83vnuwDXJQliMCTEmpdTG9UQ/gm8yzJWkUBpb\u0000",
                "validation": "U2FsdGVkX1+NtjhEJU9qkGUxkqUjhSz8FZVXDsMMwlBwwzhOYHvsAxMzjBBEYYk4axYE6GLI44lZsDHWo7ltacWZcLnJETs9e3kmq6NTBYbwrwV6a9eH/lXNmL1nVhdt4TplmnJc7bF/mwZquZ1HTMbX8xTK3/LF3STA8xLKjDrjO8DQBitQfRtr43mN5eSB0Vn9skfGbENfzjxj0hpbqxKhEvC4ijFf8jXvyrjt9hr2HX1C4aJXJHAfkvrp5DMzzG2gMGzo4wLPqH5PrApIoZQD9ORRmmvKkoJ868yn6QKaQhynOP0Jt63sgvw0d0NmNztXClFKmsOYe3he+UbIQnPNCWEyK6/+gU+Rflb71tdpYsUFMeSH1AlTvyBW/jxqAH44/jzNIFILqPvd3dHqgo/I1OJzkn0ShN8gLZ2mYs9rMaCiGggiUd8GJtOeke90jFFCPqqb3D82uzBnbxJ49iziMHC19JFmSqi27leXR0vqr+2wX88oROAb54phSNs3islM3JxxnNqwj8xptOuzRTp6RaGt+9PKZh4vFDDehlM6wc4UwQrf92lSKFeT7Hha5KXiqb356Z4aAjFykvkMzgLaAICQOTNK5CtsOSwGtfl64LzOmN7Tk7LR2U70eUa0h2KCoxYhe+AaIQPEUUGKFMQ4lGsqZ10XAhRyefiFEUrMsORdFf5qbaKsLGudzNaU/t5megiRUN7X4vo3YUz/YLonHc2q2FO3n2RuiUY+L+qg5mI+lHwMFQs+1OyrUWvimp93XhmIc0PoSRrU95JGxY5CSxUkvso7aBN4R1tPqKyf6HZuAu80RUvJj6Lk5ylYD5z4oSrQ79wRhjIVW06VzZUSGUVS1+rTcnNDTpPfDtC2alr10fkljSYDDqypwFW4+J55+k70CRjLl39Ikt5M1rrT7YdrgzBF4a4XS0w9oKJPGI741Pr/EaupuKh49QE+FHnRed1+upRW3FtF+lI7P6+GnDjxWhZZFzX16OJlCRpKNc3+Aa4fEyv++k4whhOfwssIqeefy37Oe1fgjX8AgGhKUswuyCME8ctP/jpvqliKvCPHPzyHohquL3yn9bkZJsAAGP7bYok9Na0AcxErEVdmGGEadLDiXGVgILvXk5AxGvWVLp4dt5mctajx0mHClRz7XSF4YU0zftcZ84OCIbagbvH6TJy0iQv9GVTNGBE9zTH2GhDdHv/UFzXPN3f8rDGHZdBL1o9c5mEu3AoGi4pDokH0M1+mqyERXJhgkszKhFN+PMZfZT/92azIZNR7+GUCW9D1MI52wx00OuQCKskD8FhmMH6n6GpndP84YvWardOz7OTErxfgYpnI3g0mpy7UD5RuTIXSgFUAQDv8TC/EnuPFQBfMPlslkPCsSFR2mRemoGmxlQ7IARndAZos\u0000"
            }, {
                "iterations": 42,
                "level": "SL5",
                "identifier": "AFB7B96135784496A1DB55BF6160C75B",
                "validation": "U2FsdGVkX1/tddu3MyoCBwYvnWwgsP9wp4PKAZL32+lreFRD3g+79+KawId2c/E/nIecGDLHIDvhUIr10YfK4iFbpERa2bCSXHpXfbQZJiInJUBukZ92159mrIS/6tivvwqe5GRc8Pe/0kPkdfpQOSHU6ceWWrB0fDJdIh6ZQp1NFDCrY+gUT/ZLWz9reO6NyKfipfpptfolY+2Hs06p4grmzpaXEz0kItoRUsQSxqwIa72/8AbZdloWGGUSCt06cOYI7FBFh2iaS1X41CX0AUNkZtu5sdYGGgbjWx+Alb/XjyRwBjlCCNv/UFghDGtAY7bW3qKvfWtzCeHwfzmbQ3t48/ABtjvdfS1WWxqLufdTLdCafPVLXhYKYGvETKcx7vSzUvZ+OneE9cRzcUf0zTVuE7BFbfWSCE2j+CbInNX+MYHoR9MI7PUhC+IZVkDcTPRRLtVwDkJpRzAS0rFLwvcjsRPbA1GVrEYDn8I8Jj6TuW7bzmz1nj3INFu4NSqy/R/sn6Jjbb5D2RWIlumzhxusg8NhY4IgTbZlnxgL+CQAk0EjJWKExfyWNQl43+io0dwp/vkSYbiyYg9quCek4H3XqAu8KFcyoXfO623vdl7oUkOhb3dPdAQ4DUE0sG8ostkiZTBc2lSqMeE0Y4YlTJg4C9FbEl4saRXNAsXoDq4EvbQNBE7ivfil9RsihAvPELJ3QrijrtO7GATyDS5fFbhF/4RVmQzFFV1BQy2RbJ3MQCo+0PUJ5GDVpBAVUDrkVm3xvBbb6kCPrBxFnd2xOEQv086BdGGkEOPYtUj5ySd6+EfAeAU/p1BzloO1T/hlkOI1dk4G3xxGORup2TnbHWiNKEOwQQfLMEPoFx7lO+66TZ/F3K+5v43XgOA6jew17SwrXUOt2fJBHtrim3hOUuq/SPbCSqrYXO3a9rcCN0Sd2Xb357glTr9O0DYKL10A56OdtXPGjytF6v+cFsuA2qu0kWUs+OfShZUWa8DyGJ8p7XEMeoJJgv6QetRIsZZmdsYryQyG2f4q9qmHVYhWo/gYBxVOePl2KH1qSC+0Tl0pIphLwlTatVMtwsjt4VMFPuiBgwAoYr/7YpDK7n28rSUOhRjs1YZpuZgj/iDfLEgnmzrlJ5tFwaYd71wHir0ER1uPL1NBYyozbQWbc8yzZo/+2ZkM5YzF21qr9tyqzM11jcwTAXPs6m9i+tPIL4jXcJMjL/FuEncOHrtv5u2WBIHzXyQcLZB8EcxCkonJoxW1VOUvA2wC54BtQCsCKUAzu3p1BjOiv5qGccabnrnZ6Pr96dQ0+vVfFQM7lrzOhub42qkZ/DSmd6JxhU9PBxaolPYSdiAU7gqusmP3EtGTbHxzz4ICYkSVUEcanj1j293d0Qs8r+w5UKvqLIf53cfn\u0000",
                "data": "U2FsdGVkX19QV/gRJ/Cd9R34TNjzeExOuC5oUPwTFvYorGYxGKrxOMzy0d64vMLxjDMV4ekET9c6JwmluCKfYpklqcYscIMFHp1O46pne01Ib+chbSCsvGKHvpKXVuoPaPvOn8QJ1NJYGR6KsUpQWVPqWv7V6dvSHJD+Rd48iJRbdPg0IBXfq7BvTepfUTuFSGN6SGzVhhcHyzYUmJ8UYMfLtU+Oyk2gUapHpI0JdRms6fL1uefWLQzy8boK5Yk4sBjxh5G5AW7URkuaWM0TTQwpk5hiBgkEw/0pRBb3IHtrzo3Tk95SGht0yKexMcyladcWXV5o444Cf+JrQGzixbFyUz7jmbID0qTmGkV2YSQ5EsTfFXQkpprg3oGGaDg4W+cJvRVYm7E2cDC4FLkcjVPlYKAluzzJui5A4AiPcy8z3A28INIK2DGyUWmgTRG8Ym7N2F9yomAqu7RjA4hY11PhGxW80eU60z3IgOdFm++nsX7WLhDbF93kFr3FLYeHXTPuH4QzZbgpbzpZ4HQLwQghzENLKMpGlFVFJUq0kQTxmeb0vmwQs2EkG+jNbPg8C0wKXunNSZuYtDnFPDYA87Dj6Ptw1yVf82MJOw2v/dTe8lnUkbtXHtSLRETsGI+WohmvHOrGpRaQ17cljxjxKB8obUBqNugsh7bFUxe7Xyid3Ske2ccd907a7AtVNbBsMDq0p4HPhCLfrmhkNh16C1d8UzJWrGBUkUdHGet8mJjla92LeSck0fAuJxsFpSQsvBCffraQhfRc8IjeYV5uGhGUL4XU7ryuDhsx11dFQqoDvtQNbN7RjN5Lx6XdnowWSgxzw1ztZi+D6XcfmFmrQLGUhONIOo4Ghp81EdGu/WbSENowXOLheeu7ZW7x8k6zDfNJBk29egXNvwzls+Es1eq6s7Qr6optzEc1z0MwuokTYGq8VpdUZeo3c/Or322v9nUhXDddKO9OCQ5zwN5ex4SYD/Dx4kk3PTVITlSzpjso36HvNy0zCiXezwuVif0r6Gv4kFPodYhBUb4t2cNotWOSxmQPjO5OX5D3ufi+S7eh/+S8DfQWHetpWcQ5fZJaV8khxZc5/PNlwSetn3E+MoLJZb3NkGVed1OAeqIhMwMwiR+d6ykQKqghasWMhQQxk1Tf/g4F+ar3CUhX+YAz/dAfZsa3pP7UzThUNigTe/mF8hwZWUoqTpq43FATGZnPgjYlLdmnmCdokQbyXIqt9lMCjPV6k0RJodLVd5CW5DbzqIoxV/KH4K3S/qqaQBL2Vl3T1pzg+Z3+xFdnFC9Okr+ePtVQkuSowUMqqBl5vOPq+n6BvgziRbCY41RLF3nyFFFnSr9vq7ZAy0WgNmkQpPfO46dUUrEL/DSqfD93/tsHsl/psy1JORPs57Or6JPc\u0000"
            }]
        }"#;

        let decoded: EncryptionKeyList = json::decode(encoded.as_slice()).unwrap();

        let salt: Vec<u8> = vec![ 0x83, 0x1f, 0xa8, 0xf6, 0x4f, 0x26, 0x1e, 0x44 ];
        assert!(decoded.list[0].iterations == 10000);
        assert!(decoded.list[0].level.as_slice() == "SL3");
        assert!(decoded.list[0].identifier.as_slice() == "408C2E2D6A8B480893068AC602FA6D7B");
        assert!(decoded.list[0].data.salt == salt);

        let salt2: Vec<u8> = vec![ 0x50, 0x57, 0xf8, 0x11, 0x27, 0xf0, 0x9d, 0xf5 ];
        assert!(decoded.list[1].iterations == 42);
        assert!(decoded.list[1].level.as_slice() == "SL5");
        assert!(decoded.list[1].identifier.as_slice() == "AFB7B96135784496A1DB55BF6160C75B");
        assert!(decoded.list[1].data.salt == salt2);
    }
}
