use dkg_cli::user::{
    actions::{keygen, phase1, phase2, phase3, try_finalize},
    opts::{Command, DKGOpts},
};

use gumdrop::Options;
use std::process;

use threshold_bls::{
    curve::zexe::{self as bls12_377, PairingCurve as BLS12_377},
    sig::bls::G2Scheme,
};

// TODO: In the future, we may want to make the CLI work with both G1
// and G2 schemes, and/or different curves. Keeping it simple for now.
type Curve = bls12_377::G2Curve;
type Scheme = G2Scheme<BLS12_377>;

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
