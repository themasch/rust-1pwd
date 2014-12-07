use rust_crypto::aes::{cbc_decryptor, KeySize};
use rust_crypto::blockmodes::NoPadding;
use rust_crypto::symmetriccipher::Decryptor;
use rust_crypto::buffer::{ReadBuffer, RefReadBuffer,RefWriteBuffer};

pub fn decrypt_aes(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {

    assert!(key.len() == 16);
    assert!(iv.len() == 16);

    // create aes encryptor
    let mut enc = cbc_decryptor(KeySize::KeySize128, key, iv, NoPadding);
    let mut data = RefReadBuffer::new(data);
    let mut key_buffer = Vec::from_elem(data.capacity(), 0);

    {
        let mut output = RefWriteBuffer::new(key_buffer.as_mut_slice());
        enc.decrypt(&mut data, &mut output, true);
    }


    let padding_size = key_buffer[key_buffer.len() - 1];

    if padding_size >= 16 {
        return key_buffer
    }
    else {
        let tmp = key_buffer.slice_to(key_buffer.len() - (padding_size as uint));
        let mut ret = Vec::new();
        ret.push_all(tmp);
        return ret
    }
}
