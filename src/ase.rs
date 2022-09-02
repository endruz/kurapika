// Std
use std::error::Error;

// External
use crypto::aes::KeySize::KeySize128;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use rand::Rng;

fn aes128_ecb_encrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = Vec::<u8>::new();
    let mut encrypt = crypto::aes::ecb_encryptor(KeySize128, key, PkcsPadding);
    let mut read_buffer = RefReadBuffer::new(text);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    encrypt
        .encrypt(&mut read_buffer, &mut write_buffer, true)
        .unwrap();

    result.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );
    Ok(result)
}

fn aes128_ecb_decrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = Vec::<u8>::new();
    let mut decrypt = crypto::aes::ecb_decryptor(KeySize128, key, PkcsPadding);
    let mut read_buffer = RefReadBuffer::new(text);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    decrypt
        .decrypt(&mut read_buffer, &mut write_buffer, true)
        .unwrap();
    result.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );
    Ok(result)
}

/// 加密
pub fn encrypt(ase_key: &str, text: &str) -> String {
    println!("encrypt text: {:?}", text);
    println!("encrypt ase_key: {}", ase_key);
    let ase_enc_data = aes128_ecb_encrypt(ase_key.as_bytes(), text.as_bytes()).unwrap();
    let encrypt_message = hex::encode_upper(ase_enc_data);
    encrypt_message
}

/// 解密
pub fn decrypt(ase_key: &str, text: &str) -> String {
    let text = &*hex::decode(text).unwrap();
    println!("decrypt text: {:?}", text);
    println!("decrypt ase_key: {}", ase_key);
    let ase_dec_data = aes128_ecb_decrypt(ase_key.as_bytes(), text).unwrap();
    let decrypt_message = ase_dec_data.iter().map(|&c| c as char).collect::<String>();
    decrypt_message
}

pub fn generate_ase_key() -> String {
    // 16, 24, 32 字节的 key 对应 KeySize128, KeySize192, KeySize256
    const ASE_KEY_LEN: usize = 16;
    const CHARSET: &[u8] = b"0123456789ABCDEF";

    let mut rng = rand::thread_rng();
    let ase_key: String = (0..ASE_KEY_LEN)
        .map(|_| {
            let idx: usize = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    ase_key
}
