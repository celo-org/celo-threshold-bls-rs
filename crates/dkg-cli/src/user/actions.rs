use super::opts::{FinalizeOpts, NewOpts, PublishSharesOpts, StateOpts};
use crate::CLIResult;
use rand::RngCore;
use std::fs::File;

use dkg_core::{
    node::{DKGPhase, Phase0, Phase1, Phase2, Phase2Result},
    primitives::{
        group::Group,
        states::{BundledJustification, BundledResponses, BundledShares, DKGWaitingJustification},
    },
};

use threshold_bls::{group::Curve, sig::Scheme};

pub fn keygen<S, R>(opts: NewOpts, rng: &mut R) -> CLIResult<()>
where
    S: Scheme,
    R: RngCore,
{
    // write the private key for later use
    let (private_key, public_key) = S::keypair(rng);
    let f = File::create(opts.private_key)?;
    bincode::serialize_into(&f, &private_key)?;

    // write both the index of the node and the pubkey
    let f = File::create(opts.public_key)?;
    bincode::serialize_into(&f, &opts.index)?;
    bincode::serialize_into(&f, &public_key)?;

    Ok(())
}

pub fn phase1<S, C, R>(opts: PublishSharesOpts, rng: &mut R) -> CLIResult<()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    R: RngCore,
{
    let private_key_file = File::open(opts.private_key)?;
    let pk: S::Private = bincode::deserialize_from(private_key_file)?;

    let group_file = File::open(opts.group)?;
    let group: Group<C> = bincode::deserialize_from(group_file)?;

    let phase0 = Phase0::new(pk, group)?;

    // writes the shares to the board
    let mut board = File::create(opts.output)?;
    let phase1 = phase0.run(&mut board, rng)?;

    let phase1_file = File::create(opts.out_phase)?;
    bincode::serialize_into(&phase1_file, &phase1)?;

    Ok(())
}

pub fn phase2<C: Curve>(opts: StateOpts) -> CLIResult<()> {
    let phase1_file = File::open(opts.in_phase)?;
    let phase1: Phase1<C> = bincode::deserialize_from(phase1_file)?;

    let shares_file = File::open(opts.input)?;
    let shares: Vec<BundledShares<C>> = bincode::deserialize_from(shares_file)?;

    // writes the responses to the board
    let mut board = File::create(opts.output)?;
    let phase2 = phase1.run(&mut board, &shares)?;

    let phase2_file = File::create(opts.out_phase)?;
    bincode::serialize_into(&phase2_file, &phase2)?;

    Ok(())
}

pub fn try_finalize<C: Curve>(opts: StateOpts) -> CLIResult<()> {
    let phase2_file = File::open(opts.in_phase)?;
    let phase2: Phase2<C> = bincode::deserialize_from(phase2_file)?;

    let responses_file = File::open(opts.input)?;
    let responses: Vec<BundledResponses> = bincode::deserialize_from(responses_file)?;

    // writes the justifications to the board
    let mut board = File::create(opts.output)?;
    let output = phase2.run(&mut board, &responses)?;

    let output_file = File::create(opts.out_phase)?;
    match output {
        Phase2Result::Output(out) => {
            println!("Success. Your share and threshold pubkey are written to the output.");
            bincode::serialize_into(&output_file, &out)?;
        }
        Phase2Result::GoToPhase3(p3) => {
            println!("There were complaints. Please run Phase 3.");
            bincode::serialize_into(&output_file, &p3)?;
        }
    };

    Ok(())
}

pub fn phase3<C: Curve>(opts: FinalizeOpts) -> CLIResult<()> {
    let phase3_file = File::open(opts.in_phase)?;
    let phase3: DKGWaitingJustification<C> = bincode::deserialize_from(phase3_file)?;

    let justifications_file = File::open(opts.input)?;
    let justifications: Vec<BundledJustification<C>> =
        bincode::deserialize_from(justifications_file)?;

    match phase3.process_justifications(&justifications) {
        Ok(out) => {
            println!("Success. Your share and threshold pubkey are written to the output.");
            let output_file = File::create(opts.output)?;
            bincode::serialize_into(&output_file, &out)?;
        }
        Err(err) => {
            eprintln!("DKG failed: {}", err);
        }
    };

    Ok(())
}
