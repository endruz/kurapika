// Std
use std::fs;
use std::iter;
use std::path::Path;

// External
use crypto::{digest::Digest, sha2::Sha256};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::{hash::Hash, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

const DEFAULT_PATH: &str = ".kurapika";
const PRIVATE_KEY_FILE_DEFAULT_PATH: &str = ".kurapika/id_rsa";
const PUBLIC_KEY_FILE_DEFAULT_PATH: &str = ".kurapika/id_rsa.pub";

pub fn generate_rsa_key(is_force: bool) {
    if !is_key_exist() || is_force {
        let mut rng = rand::thread_rng();

        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        match private_key.write_pkcs8_pem_file(PRIVATE_KEY_FILE_DEFAULT_PATH, LineEnding::LF) {
            Ok(_) => (), // println!("write the private_key successful"),
            Err(error) => println!("Problem write the private_key: {:?}", error),
        };

        match public_key.write_public_key_pem_file(PUBLIC_KEY_FILE_DEFAULT_PATH, LineEnding::LF) {
            Ok(_) => (), //println!("write the public_key successful"),
            Err(error) => println!("Problem write the public_key: {:?}", error),
        };
    }
}

fn is_key_exist() -> bool {
    if !Path::new(DEFAULT_PATH).exists() {
        fs::create_dir(DEFAULT_PATH).unwrap();
        false
    } else {
        Path::new(PRIVATE_KEY_FILE_DEFAULT_PATH).exists()
            && Path::new(PUBLIC_KEY_FILE_DEFAULT_PATH).exists()
    }
}

fn get_private_key() -> RsaPrivateKey {
    RsaPrivateKey::read_pkcs8_pem_file(PRIVATE_KEY_FILE_DEFAULT_PATH).unwrap()
}

fn get_public_key() -> RsaPublicKey {
    RsaPublicKey::read_public_key_pem_file(PUBLIC_KEY_FILE_DEFAULT_PATH).unwrap()
}

// 公钥加密，私钥解密
/// RSA只能加密小于（或等于）密钥长度的数据。
/// Encrypt
pub fn encrypt(text: &str) -> String {
    let mut rng = rand::thread_rng();
    let public_key = get_public_key();
    let data = text.as_bytes();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let encrypted_data = public_key
        .encrypt(&mut rng, padding, data)
        .expect("failed to encrypt");
    let encrypt_message = hex::encode_upper(encrypted_data);
    encrypt_message
}

/// Decrypt
pub fn decrypt(text: &str) -> String {
    let encrypted_data = &*hex::decode(text).unwrap();
    let private_key = get_private_key();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let decrypted_data = private_key
        .decrypt(padding, encrypted_data)
        .expect("failed to decrypt");
    let decrypt_message = decrypted_data
        .iter()
        .map(|&c| c as char)
        .collect::<String>();
    decrypt_message
}

/// 私钥签名，公钥验签
/// sign
pub fn sign(text: &str) -> String {
    let private_key = get_private_key();

    // 获取摘要
    let hashed = get_hashed(text);

    // 对摘要进行签名
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let sign_data = private_key.sign(padding, &hashed).unwrap();
    let sign_message = hex::encode_upper(sign_data);
    sign_message
}

/// verify
pub fn verify(text: &str, sign: &str) {
    let sign_data = &*hex::decode(sign).unwrap();
    let public_key = get_public_key();

    // 获取摘要
    let hashed = get_hashed(text);

    // 对签名进行验证
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let sign_result = public_key.verify(padding, &hashed, sign_data).unwrap();
    sign_result
}

fn get_hashed(text: &str) -> Vec<u8> {
    // 创建一个 Sha256 对象
    let mut hasher = Sha256::new();
    // 对内容进行摘要
    hasher.input_str(text);
    // 将摘要结果保存到 hashed 中
    let mut hashed: Vec<u8> = iter::repeat(0)
        .take((hasher.output_bits() + 7) / 8)
        .collect();
    hasher.result(&mut hashed);
    hashed
}
