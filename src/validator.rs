// Std

// External

// Internal
use crate::ase;
use crate::rsa;

pub fn verify_auth_code(auth_code: &str) -> bool {
    let ase_key = &auth_code[0..16];
    // 加密信息的长度，十六进制字符串切片转 usize
    let encrypt_message_length = usize::from_str_radix(&auth_code[16..20], 16).unwrap();
    println!("encrypt_message_length: {}", encrypt_message_length);
    // 判断 auth code 是否合格
    if 20 + encrypt_message_length >= auth_code.len() {
        return false;
    }
    let encrypt_message = &auth_code[20..20 + encrypt_message_length];
    let sign_message = &auth_code[20 + encrypt_message_length..];
    // 验证签名
    let verify = rsa::verify(encrypt_message, sign_message);
    println!("design: {:?}", verify);
    // 解密信息
    let decrypt_message = ase::decrypt(ase_key, encrypt_message);
    println!("decrypt_message: {}", decrypt_message);
    true
}
