use super::opts::{FinalizeOpts, NewOpts, PublishSharesOpts, StateOpts};
use rand::RngCore;
use std::{fs::File, io::Result as IoResult};

use dkg_core::{
    node::{DKGPhase, Phase0, Phase1, Phase2, Phase2Result},
    primitives::{
        BundledJustification, BundledResponses, BundledShares, DKGWaitingJustification, Group,
    },
};

use threshold_bls::{
    group::{Curve, Point},
    sig::Scheme,
};

pub fn keygen<S, R>(opts: NewOpts, mut rng: R) -> IoResult<()>
where
    S: Scheme,
    R: RngCore,
{
    // write the private key for later use
    let (private_key, public_key) = S::keypair(&mut rng);
    let f = File::create(opts.private_key)?;
    bincode::serialize_into(&f, &private_key).unwrap();

    // write both the index of the node and the pubkey
    let f = File::create(opts.public_key)?;
    bincode::serialize_into(&f, &opts.index).unwrap();
    bincode::serialize_into(&f, &public_key).unwrap();

    Ok(())
}

pub fn phase1<S, C>(opts: PublishSharesOpts)
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    <S as Scheme>::Signature: Point<<C as Curve>::Scalar>,
{
    let private_key_file = File::open(opts.private_key).unwrap();
    let pk: S::Private = bincode::deserialize_from(private_key_file).unwrap();

    let group_file = File::open(opts.group).unwrap();
    let group: Group<C> = bincode::deserialize_from(group_file).unwrap();

    let phase0 = Phase0::new(pk, group).unwrap();

    // writes the shares to the board
    let mut board = File::create(opts.output).unwrap();
    let phase1 = phase0.run(&mut board, false).unwrap();

    let phase1_file = File::create(opts.out_phase).unwrap();
    bincode::serialize_into(&phase1_file, &phase1).unwrap();
}

pub fn phase2<C: Curve>(opts: StateOpts) {
    let phase1_file = File::open(opts.in_phase).unwrap();
    let phase1: Phase1<C> = bincode::deserialize_from(phase1_file).unwrap();

    let shares_file = File::open(opts.input).unwrap();
    let shares: Vec<BundledShares<C>> = bincode::deserialize_from(shares_file).unwrap();

    // writes the responses to the board
    let mut board = File::create(opts.output).unwrap();
    let phase2 = phase1.run(&mut board, &shares).unwrap();

    let phase2_file = File::create(opts.out_phase).unwrap();
    bincode::serialize_into(&phase2_file, &phase2).unwrap();
}

pub fn try_finalize<C: Curve>(opts: StateOpts) {
    let phase2_file = File::open(opts.in_phase).unwrap();
    let phase2: Phase2<C> = bincode::deserialize_from(phase2_file).unwrap();

    let responses_file = File::open(opts.input).unwrap();
    let responses: Vec<BundledResponses> = bincode::deserialize_from(responses_file).unwrap();

    // writes the justifications to the board
    let mut board = File::create(opts.output).unwrap();
    let output = phase2.run(&mut board, &responses).unwrap();

    let output_file = File::create(opts.out_phase).unwrap();
    match output {
        Phase2Result::Output(out) => {
            println!("Success. Your share and threshold pubkey are written to the output.");
            bincode::serialize_into(&output_file, &out).unwrap();
        }
        Phase2Result::GoToPhase3(p3) => {
            println!("There were complaints. Please run Phase 3.");
            bincode::serialize_into(&output_file, &p3).unwrap();
        }
    }
}

pub fn phase3<C: Curve>(opts: FinalizeOpts) {
    let phase3_file = File::open(opts.in_phase).unwrap();
    let phase3: DKGWaitingJustification<C> = bincode::deserialize_from(phase3_file).unwrap();

    let justifications_file = File::open(opts.input).unwrap();
    let justifications: Vec<BundledJustification<C>> =
        bincode::deserialize_from(justifications_file).unwrap();

    match phase3.process_justifications(&justifications) {
        Ok(out) => {
            println!("Success. Your share and threshold pubkey are written to the output.");
            let output_file = File::create(opts.output).unwrap();
            bincode::serialize_into(&output_file, &out).unwrap();
        }
        Err(err) => {
            eprintln!("DKG failed: {}", err);
        }
    }
}
