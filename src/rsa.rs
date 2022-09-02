// Std
use std::fs;
use std::path::Path;

// External
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

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

/// Encrypt
pub fn encrypt(text: &str) -> String {
    let mut rng = rand::thread_rng();
    let public_key = get_public_key();
    let data = text.as_bytes();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key.encrypt(&mut rng, padding, data).expect("failed to encrypt");
    // assert_ne!(&data[..], &enc_data[..]);
    String::from_utf8(enc_data).unwrap()
}

/// Decrypt
pub fn decrypt(text: &str) -> String {
    let enc_data = text.as_bytes();
    let private_key = get_private_key();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key.decrypt(padding, enc_data).expect("failed to decrypt");
    // assert_eq!(&data[..], &dec_data[..]);
    String::from_utf8(dec_data).unwrap()
}
