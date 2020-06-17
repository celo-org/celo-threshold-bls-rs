use dkg_cli::{actions::*, opts::*};

use gumdrop::Options;
use std::process;

use threshold_bls::schemes::bls12_377::{G2Curve as Curve, G2Scheme as Scheme};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = DKGOpts::parse_args_default_or_exit();

    let command = opts.command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", DKGOpts::usage());
        process::exit(2)
    });

    let rng = &mut rand::thread_rng();

    match command {
        Command::Keygen(opts) => keygen(opts, rng)?,
        Command::Run(opts) => run::<Scheme, Curve, _>(opts, rng).await?,
        Command::Start(opts) => start(opts).await?,
        Command::Deploy(opts) => deploy(opts).await?,
        Command::Allow(opts) => allow(opts).await?,
    };

    Ok(())
}
