// External

// Internal
use crate::ase;
use crate::rsa;
use crate::auth::AuthInfo;

pub fn generate_auth_code(auth_info: AuthInfo) -> String {
    let ase_key = ase::generate_ase_key();

    let encrypt_message = ase::encrypt(&ase_key, &auth_info.to_string());
    println!("encrypt_message: {}", encrypt_message);

    let encrypt_message_length = encrypt_message.len();
    println!("encrypt_message_length: {}", encrypt_message_length);

    rsa::generate_rsa_key(false);

    let sign = rsa::encrypt(&encrypt_message);
    println!("sign: {}", sign);

    let design = rsa::decrypt(&sign);
    println!("design: {}", design);


    // let decrypt_message = ase::decrypt(&ase_key, &encrypt_message);
    let decrypt_message = ase::decrypt(&ase_key, &design);
    println!("decrypt_message: {}", decrypt_message);
    encrypt_message
}
