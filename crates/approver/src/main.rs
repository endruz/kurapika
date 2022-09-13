// Module
mod client;

// Extern crate
extern crate clap;

// Std
use std::process;

// External
use clap::Parser;
use kr::{generator, AuthInfo};

// Internal
use crate::client::Args;

fn main() {
    // 获取参数
    let args = Args::parse();
    // 生成认证信息
    let auth_info = AuthInfo::register(&args.file).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });
    // 生成授权码
    let auth_code = generator::generate_auth_code(&auth_info).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });
    // 保存授权码
    generator::save_auth_code(&auth_code).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });

    println!("Generate auth code successfully!");

    if args.show {
        println!("Print authentication information:\n");
        println!("{}", auth_info.to_string());
    }
}
