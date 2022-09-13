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

/// Verify authorization code
pub fn verify_auth_code(auth_code: &str) -> Result<(), KurapikaError> {
    if auth_code.len() <= 20 {
        return Err(KurapikaError::VerifyFailure);
    }

    let ase_key = &auth_code[0..16];
    // Length of encrypted message, hex string sliced to usize
    let encrypt_message_length = match usize::from_str_radix(&auth_code[16..20], 16) {
        Ok(length) => length,
        Err(_) => return Err(KurapikaError::VerifyFailure),
    };

    if 20 + encrypt_message_length >= auth_code.len() {
        return Err(KurapikaError::VerifyFailure);
    }

    let encrypt_message = &auth_code[20..20 + encrypt_message_length];
    let sign_message = &auth_code[20 + encrypt_message_length..];

    rsa::verify(encrypt_message, sign_message)?;

    let decrypt_message = ase::decrypt(ase_key, encrypt_message)?;
    let auth_info = match AuthInfo::from_str(&decrypt_message) {
        Ok(obj) => obj,
        Err(_) => return Err(KurapikaError::VerifyFailure),
    };
    auth_info.verify()?;

    Ok(())
}

/// Load authorization code
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
