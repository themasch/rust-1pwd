use openssl::crypto::symm::Type;
use openssl::crypto::symm::decrypt;

pub fn decrypt_aes(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {

    assert!(key.len() == 16);
    assert!(iv.len() == 16);

    let tmp = decrypt(Type::AES_128_CBC, key, iv.to_vec(), data);
    println!("{:?} {:?}", data.len(), tmp.len());
    return tmp;
    // create aes encryptor
    /*let mut enc = cbc_decryptor(KeySize::KeySize128, key, iv, PkcsPadding);
    let mut data = RefReadBuffer::new(data);
    let mut key_buffer = Vec::from_elem(data.capacity(), 0);
    let mut remaining: uint;
    {
        let mut output = RefWriteBuffer::new(key_buffer.as_mut_slice());
        let result = enc.decrypt(&mut data, &mut output, true);
        remaining = output.remaining();
    }

    //key_buffer.sh
    return key_buffer.slice_to(key_buffer.len() - remaining).to_vec();
    */
}
