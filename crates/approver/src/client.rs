// External
use clap::Parser;

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
