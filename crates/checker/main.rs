//! # kr-checker
//!
//! A command line tool for verifying authorization codes

// Extern crate
extern crate clap;

// Std
use std::process;

// External
use clap::Parser;
use kr::validator;

// Internal

/// A structure to store arguments
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {}

fn main() {
    // Get arguments
    let _args = Args::parse();
    // Load authorization code
    let auth_code = match validator::load_auth_code() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {:?}", err);
            process::exit(1);
        }
    };
    // Verify authorization code
    match validator::verify_auth_code(&auth_code) {
        Ok(_) => println!("Verification passed !!!"),
        Err(err) => {
            eprintln!("error: {:?}", err);
            process::exit(1);
        }
    };
}
