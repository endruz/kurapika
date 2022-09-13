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
use crate::cfg;
use crate::error::KurapikaError;

/// Generate RSA key
pub fn generate_rsa_key(is_force: bool) -> Result<(), KurapikaError> {
    if !is_key_exist() || is_force {
        let mut rng = rand::thread_rng();

        let bits = 2048;
        let private_key = match RsaPrivateKey::new(&mut rng, bits) {
            Ok(key) => key,
            Err(_) => return Err(KurapikaError::GenerateKeyFailure),
        };
        let public_key = RsaPublicKey::from(&private_key);

        // Create .kurapika
        if !Path::new(cfg::DEFAULT_PATH).exists() {
            match fs::create_dir(cfg::DEFAULT_PATH) {
                Ok(_) => (),
                Err(_) => return Err(KurapikaError::GenerateKeyFailure),
            };
        }

        // Generate id_rsa
        match private_key.write_pkcs8_pem_file(cfg::PRIVATE_KEY_FILE_DEFAULT_PATH, LineEnding::LF) {
            Ok(_) => (),
            Err(_) => return Err(KurapikaError::GenerateKeyFailure),
        };

        // Generate id_rsa.pub
        match public_key
            .write_public_key_pem_file(cfg::PUBLIC_KEY_FILE_DEFAULT_PATH, LineEnding::LF)
        {
            Ok(_) => (),
            Err(_) => return Err(KurapikaError::GenerateKeyFailure),
        };
    }
    Ok(())
}

/// Determine if the key exists
fn is_key_exist() -> bool {
    Path::new(cfg::PRIVATE_KEY_FILE_DEFAULT_PATH).exists()
        && Path::new(cfg::PUBLIC_KEY_FILE_DEFAULT_PATH).exists()
}

/// Get private key
fn get_private_key() -> Result<RsaPrivateKey, KurapikaError> {
    match RsaPrivateKey::read_pkcs8_pem_file(cfg::PRIVATE_KEY_FILE_DEFAULT_PATH) {
        Ok(private_key) => Ok(private_key),
        Err(_) => Err(KurapikaError::GetKeyFailure),
    }
}

/// Get public key
fn get_public_key() -> Result<RsaPublicKey, KurapikaError> {
    match RsaPublicKey::read_public_key_pem_file(cfg::PUBLIC_KEY_FILE_DEFAULT_PATH) {
        Ok(public_key) => Ok(public_key),
        Err(_) => Err(KurapikaError::GetKeyFailure),
    }
}

/// Public key encryption
///
/// RSA can only encrypt data that is less than (or equal to) the length of the key.
pub fn encrypt(text: &str) -> Result<String, KurapikaError> {
    let mut rng = rand::thread_rng();
    let public_key = get_public_key()?;
    let data = text.as_bytes();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let encrypted_data = match public_key.encrypt(&mut rng, padding, data) {
        Ok(data) => data,
        Err(_) => return Err(KurapikaError::EncryptionFailure),
    };
    let encrypt_message = hex::encode_upper(encrypted_data);
    Ok(encrypt_message)
}

/// Private key decryption
pub fn decrypt(text: &str) -> Result<String, KurapikaError> {
    let encrypted_data = match hex::decode(text) {
        Ok(h) => h,
        Err(_) => return Err(KurapikaError::DecryptionFailure),
    };
    let private_key = get_private_key()?;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let decrypted_data = match private_key.decrypt(padding, encrypted_data.as_slice()) {
        Ok(data) => data,
        Err(_) => return Err(KurapikaError::DecryptionFailure),
    };

    let decrypt_message = decrypted_data
        .iter()
        .map(|&c| c as char)
        .collect::<String>();
    Ok(decrypt_message)
}

/// Private key signature
pub fn sign(data: &str) -> Result<String, KurapikaError> {
    let private_key = get_private_key()?;

    // Get summary
    let hashed = get_hashed(data);

    // Signing of the summary
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let sign_data = match private_key.sign(padding, &hashed) {
        Ok(data) => data,
        Err(_) => return Err(KurapikaError::SignFailure),
    };
    let sign_message = hex::encode_upper(sign_data);

    Ok(sign_message)
}

/// Public key verification
pub fn verify(data: &str, sign: &str) -> Result<(), KurapikaError> {
    let sign_data = match hex::decode(sign) {
        Ok(h) => h,
        Err(_) => return Err(KurapikaError::SignVerifyFailure),
    };
    let public_key = get_public_key()?;

    // Get summary
    let hashed = get_hashed(data);

    // Verification of signatures
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));

    match public_key.verify(padding, &hashed, sign_data.as_slice()) {
        Ok(_) => Ok(()),
        Err(_) => Err(KurapikaError::SignVerifyFailure),
    }
}

/// Get Summary
fn get_hashed(data: &str) -> Vec<u8> {
    // Create a Sha256 object
    let mut hasher = Sha256::new();
    // Summary of content
    hasher.input_str(data);
    // Save summary results to hashed
    let mut hashed: Vec<u8> = iter::repeat(0)
        .take((hasher.output_bits() + 7) / 8)
        .collect();
    hasher.result(&mut hashed);

    hashed
}
