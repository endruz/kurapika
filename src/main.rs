// #[macro_use]
// extern crate clap;
extern crate hex;

// Std
use std::process;

// External
// use clap::{Arg, Command};

// Internal
use crate::auth::AuthInfo;
use crate::generator::generate_auth_code;

mod ase;
mod auth;
mod error;
#[cfg(feature = "generator")]
mod generator;
mod rsa;
#[cfg(feature = "validator")]
mod validator;

fn main() {
    // let matches = Command::new(crate_name!())
    //     .version(crate_version!())
    //     .author(crate_authors!())
    //     .about(crate_description!())
    //     .arg(
    //         Arg::with_name("KEY")
    //             .help("Key to query from the TOML file")
    //             .required(true)
    //             .index(1),
    //     )
    //     .arg(
    //         Arg::with_name("FILE")
    //             .help("A TOML file to load")
    //             .required(true)
    //             .index(2),
    //     )
    //     .get_matches();

    let app_name = String::from("XXX-service");
    let customer_name = String::from("XXXX公司");
    let deploy_date = String::from("2022-09-01");
    let expire_date = String::from("2022-09-30");
    let auth_info = AuthInfo::new(app_name, customer_name, deploy_date, expire_date)
        .unwrap_or_else(|err| {
            eprintln!("error: {:?}", err);
            process::exit(1);
        });
    let auth_code = generate_auth_code(auth_info).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });

    // let auth_code = String::from("123");
    // println!("auth_code: {}", auth_code);

    match validator::verify_auth_code(&auth_code) {
        Ok(_) => println!("Verification passed !!!"),
        Err(err) => {
            eprintln!("error: {:?}", err);
            process::exit(1);
        }
    };
}
