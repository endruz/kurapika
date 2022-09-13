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

/// Generate authorization code
pub fn generate_auth_code(auth_info: &AuthInfo) -> Result<String, KurapikaError> {
    let ase_key = ase::generate_ase_key();
    let encrypt_message = ase::encrypt(&ase_key, &auth_info.to_string())?;

    // The length of the encrypted message is converted to a hexadecimal string of length 4
    // The maximum supported length of encrypt_message is 16^4 - 1 = 65,535
    let encrypt_message_length = format!("{:0>4X}", encrypt_message.len());

    rsa::generate_rsa_key(false)?;
    let sign = rsa::sign(&encrypt_message)?;
    let auth_code = format!("{ase_key}{encrypt_message_length}{encrypt_message}{sign}");

    Ok(auth_code)
}

/// Save authorization code
pub fn save_auth_code(auth_code: &str) -> Result<(), KurapikaError> {
    // Create .kurapika
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
