use dkg_cli::{
    actions::{keygen, phase1, phase2, phase3, try_finalize},
    opts::{Command, DKGOpts},
};

use gumdrop::Options;
use std::process;

use threshold_bls::schemes::bls12_377::{G2Curve as Curve, G2Scheme as Scheme};

fn main() {
    let opts = DKGOpts::parse_args_default_or_exit();

    let command = opts.command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", DKGOpts::usage());
        process::exit(2)
    });

    match command {
        Command::New(opts) => keygen::<Scheme, _>(opts, &mut rand::thread_rng()),
        Command::PublishShares(opts) => phase1::<Scheme, Curve, _>(opts, &mut rand::thread_rng()),
        Command::PublishResponses(opts) => phase2::<Curve>(opts),
        Command::TryFinalize(opts) => try_finalize::<Curve>(opts),
        Command::Finalize(opts) => phase3::<Curve>(opts),
    }
    .expect("command failed");
}
