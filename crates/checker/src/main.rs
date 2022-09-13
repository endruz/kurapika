// Module
mod client;

// Extern crate
extern crate clap;

// Std
use std::process;

// External
use clap::Parser;
use kr::validator;

// Internal
use crate::client::Args;

fn main() {
    // 获取参数
    let _args = Args::parse();
    // 加载授权码
    let auth_code = match validator::load_auth_code() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {:?}", err);
            process::exit(1);
        }
    };
    // 校验授权码
    match validator::verify_auth_code(&auth_code) {
        Ok(_) => println!("Verification passed !!!"),
        Err(err) => {
            eprintln!("error: {:?}", err);
            process::exit(1);
        }
    };
}
