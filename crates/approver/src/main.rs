// #[macro_use]
// extern crate clap;

// Std
use std::process;

// External
// use clap::{Arg, Command};
use kr::{generator, AuthInfo};

// Internal

fn main() {
    let app_name = String::from("XXX-service");
    let customer_name = String::from("XXXX公司");
    let deploy_date = String::from("2022-09-01");
    let expire_date = String::from("2022-09-30");
    let auth_info = AuthInfo::new(app_name, customer_name, deploy_date, expire_date)
        .unwrap_or_else(|err| {
            eprintln!("error: {:?}", err);
            process::exit(1);
        });
    let auth_code = generator::generate_auth_code(auth_info).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });
    println!("{}", auth_code)
}
