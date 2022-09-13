//! # kr-approver
//!
//! A command line tool to generate authorization code

// Extern crate
extern crate clap;

// Std
use std::process;

// External
use clap::Parser;
use kr::{generator, AuthInfo};

// Internal

/// A structure to store arguments
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Path to registration file
    #[clap(value_parser)]
    pub file: String,

    /// Print authentication information
    #[clap(short, long)]
    pub show: bool,
}

fn main() {
    // Get arguments
    let args = Args::parse();
    // Generate authentication information
    let auth_info = AuthInfo::register(&args.file).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });
    // Generate authorization code
    let auth_code = generator::generate_auth_code(&auth_info).unwrap_or_else(|err| {
        eprintln!("error: {:?}", err);
        process::exit(1);
    });
    // Save authorization code
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
