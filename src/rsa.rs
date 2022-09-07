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

// Internal
use crate::error::KurapikaError;

const DEFAULT_PATH: &str = ".kurapika";
const PRIVATE_KEY_FILE_DEFAULT_PATH: &str = ".kurapika/id_rsa";
const PUBLIC_KEY_FILE_DEFAULT_PATH: &str = ".kurapika/id_rsa.pub";

pub fn generate_rsa_key(is_force: bool) -> Result<(), KurapikaError> {
    if !is_key_exist() || is_force {
        let mut rng = rand::thread_rng();

        let bits = 2048;
        let private_key = match RsaPrivateKey::new(&mut rng, bits) {
            Ok(key) => key,
            Err(_) => return Err(KurapikaError::GenerateKeyFailure),
        };
        let public_key = RsaPublicKey::from(&private_key);

        // 创建 .kurapika
        if !Path::new(DEFAULT_PATH).exists() {
            match fs::create_dir(DEFAULT_PATH) {
                Ok(_) => (),
                Err(_) => return Err(KurapikaError::GenerateKeyFailure),
            };
        }

        // 生成 id_rsa
        match private_key.write_pkcs8_pem_file(PRIVATE_KEY_FILE_DEFAULT_PATH, LineEnding::LF) {
            Ok(_) => (),
            Err(_) => return Err(KurapikaError::GenerateKeyFailure),
        };

        // 生成 id_rsa.pub
        match public_key.write_public_key_pem_file(PUBLIC_KEY_FILE_DEFAULT_PATH, LineEnding::LF) {
            Ok(_) => (),
            Err(_) => return Err(KurapikaError::GenerateKeyFailure),
        };
    }
    Ok(())
}

fn is_key_exist() -> bool {
    Path::new(PRIVATE_KEY_FILE_DEFAULT_PATH).exists()
        && Path::new(PUBLIC_KEY_FILE_DEFAULT_PATH).exists()
}

fn get_private_key() -> Result<RsaPrivateKey, KurapikaError> {
    match RsaPrivateKey::read_pkcs8_pem_file(PRIVATE_KEY_FILE_DEFAULT_PATH) {
        Ok(private_key) => Ok(private_key),
        Err(_) => Err(KurapikaError::GetKeyFailure),
    }
}

fn get_public_key() -> Result<RsaPublicKey, KurapikaError> {
    match RsaPublicKey::read_public_key_pem_file(PUBLIC_KEY_FILE_DEFAULT_PATH) {
        Ok(public_key) => Ok(public_key),
        Err(_) => Err(KurapikaError::GetKeyFailure),
    }
}

// // 公钥加密，私钥解密
// /// RSA只能加密小于（或等于）密钥长度的数据。
// /// Encrypt
// pub fn encrypt(text: &str) -> Result<String, KurapikaError> {
//     let mut rng = rand::thread_rng();
//     let public_key = get_public_key()?;
//     let data = text.as_bytes();
//     let padding = PaddingScheme::new_pkcs1v15_encrypt();
//     let encrypted_data = match public_key.encrypt(&mut rng, padding, data) {
//         Ok(data) => data,
//         Err(_) => return Err(KurapikaError::EncryptionFailure)
//     };
//     let encrypt_message = hex::encode_upper(encrypted_data);
//     Ok(encrypt_message)
// }

// /// Decrypt
// pub fn decrypt(text: &str) -> Result<String, KurapikaError> {
//     let encrypted_data = match hex::decode(text) {
//         Ok(h) => h,
//         Err(_) => return Err(KurapikaError::DecryptionFailure)
//     };
//     let private_key = get_private_key()?;
//     let padding = PaddingScheme::new_pkcs1v15_encrypt();
//     let decrypted_data = match private_key.decrypt(padding, encrypted_data.as_slice()) {
//         Ok(data) => data,
//         Err(_) => return Err(KurapikaError::DecryptionFailure)
//     };

//     let decrypt_message = decrypted_data
//         .iter()
//         .map(|&c| c as char)
//         .collect::<String>();
//     Ok(decrypt_message)
// }

/// 私钥签名，公钥验签
/// sign
pub fn sign(data: &str) -> Result<String, KurapikaError> {
    let private_key = get_private_key()?;

    // 获取摘要
    let hashed = get_hashed(data);

    // 对摘要进行签名
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let sign_data = match private_key.sign(padding, &hashed) {
        Ok(data) => data,
        Err(_) => return Err(KurapikaError::SignFailure),
    };
    let sign_message = hex::encode_upper(sign_data);

    Ok(sign_message)
}

/// verify
pub fn verify(data: &str, sign: &str) -> Result<(), KurapikaError> {
    let sign_data = match hex::decode(sign) {
        Ok(h) => h,
        Err(_) => return Err(KurapikaError::SignVerifyFailure),
    };
    let public_key = get_public_key()?;

    // 获取摘要
    let hashed = get_hashed(data);

    // 对签名进行验证
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));

    match public_key.verify(padding, &hashed, sign_data.as_slice()) {
        Ok(_) => Ok(()),
        Err(_) => Err(KurapikaError::SignVerifyFailure),
    }
}

fn get_hashed(data: &str) -> Vec<u8> {
    // 创建一个 Sha256 对象
    let mut hasher = Sha256::new();
    // 对内容进行摘要
    hasher.input_str(data);
    // 将摘要结果保存到 hashed 中
    let mut hashed: Vec<u8> = iter::repeat(0)
        .take((hasher.output_bits() + 7) / 8)
        .collect();
    hasher.result(&mut hashed);

    hashed
}
