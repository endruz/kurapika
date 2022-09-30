// Std

// External
use crypto::aes::KeySize::KeySize128;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use rand::Rng;

// Internal
use crate::error::KurapikaError;

fn aes128_ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, KurapikaError> {
    let mut result = Vec::<u8>::new();
    let mut encrypt = crypto::aes::ecb_encryptor(KeySize128, key, PkcsPadding);
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    if let Err(_) = encrypt.encrypt(&mut read_buffer, &mut write_buffer, true) {
        return Err(KurapikaError::EncryptionFailure);
    }

    result.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );
    Ok(result)
}

fn aes128_ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, KurapikaError> {
    let mut result = Vec::<u8>::new();
    let mut decrypt = crypto::aes::ecb_decryptor(KeySize128, key, PkcsPadding);
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    if let Err(_) = decrypt.decrypt(&mut read_buffer, &mut write_buffer, true) {
        return Err(KurapikaError::DecryptionFailure);
    }

    result.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );
    Ok(result)
}

/// ASE encrypt data
///
/// # Examples
///
/// ```
/// # use kr::ase::encrypt;
/// let ase_key = "627D213B82BA2A28";
/// let data = "hello world!";
/// let encrypt_data = encrypt(ase_key, data).unwrap();
/// assert_eq!(encrypt_data, String::from("2ECA0EBCC9E4DABEBEA7721E871DBAD9"))
/// ```
pub fn encrypt(key: &str, data: &str) -> Result<String, KurapikaError> {
    let encrypt_data = aes128_ecb_encrypt(key.as_bytes(), data.as_bytes())?;
    Ok(hex::encode_upper(encrypt_data))
}

/// ASE decrypt data
///
/// # Examples
///
/// ```
/// # use kr::ase::decrypt;
/// let ase_key = "627D213B82BA2A28";
/// let data = "2ECA0EBCC9E4DABEBEA7721E871DBAD9";
/// let decrypt_data = decrypt(ase_key, data).unwrap();
/// assert_eq!(decrypt_data, String::from("hello world!"))
/// ```
pub fn decrypt(key: &str, data: &str) -> Result<String, KurapikaError> {
    let data = match hex::decode(data) {
        Ok(h) => h,
        Err(_) => return Err(KurapikaError::DecryptionFailure),
    };
    let decrypt_data = aes128_ecb_decrypt(key.as_bytes(), data.as_slice())?;
    match String::from_utf8(decrypt_data) {
        Ok(s) => Ok(s),
        Err(_) => Err(KurapikaError::DecryptionFailure),
    }
}

/// Generate ASE key
///
/// # Examples
///
/// ```
/// # use kr::ase::generate_ase_key;
/// let ase_key = generate_ase_key();
/// println!("{}", ase_key);
/// assert_eq!(ase_key.len(), 16usize);
/// ```
pub fn generate_ase_key() -> String {
    // 16, 24, 32 bytes of key corresponding to KeySize128, KeySize192, KeySize256
    const ASE_KEY_LEN: usize = 16;
    const CHARSET: &[u8] = b"0123456789ABCDEF";

    let mut rng = rand::thread_rng();

    (0..ASE_KEY_LEN)
        .map(|_| {
            let idx: usize = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect::<String>()
}
