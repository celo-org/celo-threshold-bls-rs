use dkg_cli::coordinator::{
    actions::{combine, setup},
    opts::{Command, Opts},
};

use dkg_core::primitives::{BundledJustification, BundledResponses, BundledShares};

use gumdrop::Options;
use std::process;

use threshold_bls::schemes::bls12_377::{G2Curve as Curve, G2Scheme as Scheme};

fn main() {
    let opts = Opts::parse_args_default_or_exit();

    let command = opts.command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", Opts::usage());
        process::exit(2)
    });

    match command {
        Command::Setup(opts) => setup::<Curve, Scheme>(opts),
        Command::CombineShares(opts) => combine::<BundledShares<Curve>>(opts),
        Command::CombineResponses(opts) => combine::<BundledResponses>(opts),
        Command::CombineJustifications(opts) => combine::<BundledJustification<Curve>>(opts),
    }
    .expect("command failed");
}
