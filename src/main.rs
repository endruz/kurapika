// #[macro_use]
// extern crate clap;

extern crate hex;

// Std

// External
// use clap::{Arg, Command};

// Internal
use crate::auth::AuthInfo;
use crate::auth::{get_base_board_id, get_cpu_id, get_gpu_id};
use crate::generator::generate_auth_code;

mod ase;
mod auth;
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
    let base_board_id: String = get_base_board_id().unwrap();
    let cpu_id: String = get_cpu_id().unwrap();
    let gpu_id: Vec<String> = get_gpu_id().unwrap();

    let app_name = String::from("XXX-service");
    let customer_name = String::from("XXXX公司");
    let deploy_date = String::from("2022-09-01");
    let expire_date = String::from("2022-09-30");
    let auth_info = AuthInfo::new(app_name, customer_name, deploy_date, expire_date);
    let auth_code = generate_auth_code(auth_info);

    println!("BASE_BOARD_ID: {}", base_board_id);
    println!("CPU_ID: {}", cpu_id);
    println!("GPU_ID: {:?}", gpu_id);
    println!("auth_code: {}", auth_code);

    println!("{}", validator::verify_auth_code(&auth_code));
}
