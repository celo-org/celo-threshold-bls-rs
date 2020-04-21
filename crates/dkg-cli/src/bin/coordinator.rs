use dkg_cli::coordinator::{
    actions::{combine, setup},
    opts::{Command, Opts},
};

use dkg_core::primitives::{BundledJustification, BundledResponses, BundledShares};

use gumdrop::Options;
use std::process;

use threshold_bls::{
    curve::zexe::{self as bls12_377, PairingCurve as BLS12_377},
    sig::tblind::G2Scheme,
};

// TODO: In the future, we may want to make the CLI work with both G1
// and G2 schemes, and/or different curves. Keeping it simple for now.
type Curve = bls12_377::G2Curve;
type Scheme = G2Scheme<BLS12_377>;

fn main() {
    let opts = Opts::parse_args_default_or_exit();

    let command = opts.clone().command.unwrap_or_else(|| {
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
