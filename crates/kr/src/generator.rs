// Std
use std::fs;
use std::io::Write;
use std::path::Path;

// External

// Internal
use crate::ase;
use crate::auth::AuthInfo;
use crate::cfg;
use crate::error::KurapikaError;
use crate::rsa;

pub fn generate_auth_code(auth_info: &AuthInfo) -> Result<String, KurapikaError> {
    // 生成 ase key
    let ase_key = ase::generate_ase_key();

    // ase 加密信息
    let encrypt_message = ase::encrypt(&ase_key, &auth_info.to_string())?;

    // 加密信息的长度转为长度为 4 的十六进制字符串
    // encrypt_message 的最大支持长度为 16^4 - 1 = 65,535
    let encrypt_message_length = format!("{:0>4X}", encrypt_message.len());

    // 生成 rsa keys
    rsa::generate_rsa_key(false)?;

    // 生成 rsa 签名信息
    let sign = rsa::sign(&encrypt_message)?;

    // 组合 auth_code
    let auth_code = format!("{ase_key}{encrypt_message_length}{encrypt_message}{sign}");

    Ok(auth_code)
}

pub fn save_auth_code(auth_code: &str) -> Result<(), KurapikaError> {
    // 创建 .kurapika
    if !Path::new(cfg::DEFAULT_PATH).exists() {
        match fs::create_dir(cfg::DEFAULT_PATH) {
            Ok(_) => (),
            Err(_) => return Err(KurapikaError::SaveAuthCodeFailure),
        };
    }
    let mut file = match fs::File::create(cfg::AUTH_CODE_PATH) {
        Ok(f) => f,
        Err(_) => return Err(KurapikaError::SaveAuthCodeFailure),
    };
    match file.write_all(auth_code.as_bytes()) {
        Ok(_) => (),
        Err(_) => return Err(KurapikaError::SaveAuthCodeFailure),
    };
    Ok(())
}
