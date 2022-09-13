// Std
use std::fs::File;
use std::io::Read;

// External

// Internal
use crate::ase;
use crate::auth::AuthInfo;
use crate::cfg;
use crate::error::KurapikaError;
use crate::rsa;

pub fn verify_auth_code(auth_code: &str) -> Result<(), KurapikaError> {
    // 判断 auth code 长度是否合格
    if auth_code.len() <= 20 {
        return Err(KurapikaError::VerifyFailure);
    }
    // ase 密钥
    let ase_key = &auth_code[0..16];
    // 加密信息的长度，十六进制字符串切片转 usize
    let encrypt_message_length = match usize::from_str_radix(&auth_code[16..20], 16) {
        Ok(length) => length,
        Err(_) => return Err(KurapikaError::VerifyFailure),
    };
    // 判断 auth code 长度是否合格
    if 20 + encrypt_message_length >= auth_code.len() {
        return Err(KurapikaError::VerifyFailure);
    }
    // 加密信息
    let encrypt_message = &auth_code[20..20 + encrypt_message_length];
    // 签名信息
    let sign_message = &auth_code[20 + encrypt_message_length..];
    // 验证签名
    rsa::verify(encrypt_message, sign_message)?;
    // 解密信息
    let decrypt_message = ase::decrypt(ase_key, encrypt_message)?;
    // 生成 AuthInfo 对象
    let auth_info = match AuthInfo::from_str(&decrypt_message) {
        Ok(obj) => obj,
        Err(_) => return Err(KurapikaError::VerifyFailure),
    };
    // 验证 AuthInfo 对象信息
    auth_info.verify()?;

    Ok(())
}

pub fn load_auth_code() -> Result<String, KurapikaError> {
    let mut file = match File::open(cfg::AUTH_CODE_PATH) {
        Ok(f) => f,
        Err(_) => return Err(KurapikaError::LoadAuthCodeFailure),
    };
    let mut auth_code = String::new();
    match file.read_to_string(&mut auth_code) {
        Ok(_) => (),
        Err(_) => return Err(KurapikaError::LoadAuthCodeFailure),
    };
    Ok(auth_code)
}
