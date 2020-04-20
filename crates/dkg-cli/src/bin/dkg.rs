use dkg_cli::user::{
    actions::{keygen, phase1, phase2, phase3, try_finalize},
    opts::{DKGOpts, Command},
};

use gumdrop::Options;
use std::process;

fn main() {
    let opts = DKGOpts::parse_args_default_or_exit();

    let command = opts.clone().command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", DKGOpts::usage());
        process::exit(2)
    });

    match command {
        Command::New(opts) => keygen(opts),
        Command::PublishShares(opts) => phase1(opts),
        Command::PublishResponses(opts) => phase2(opts),
        Command::TryFinalize(opts) => try_finalize(opts),
        Command::Finalize(opts) => phase3(opts),
    }
}
