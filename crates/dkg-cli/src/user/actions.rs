use super::opts::{FinalizeOpts, NewOpts, PublishSharesOpts, StateOpts};
use crate::CLIResult;
use rand::RngCore;
use std::{fs::File, io::Write};

use dkg_core::{
    node::{DKGPhase, Phase0, Phase1, Phase2, Phase2Result, Phase3},
    primitives::{
        bundles::{BundledJustification, BundledResponses, BundledShares},
        group::{Group, Node},
        phases::DKGOutput,
    },
};

use threshold_bls::poly::Idx;
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
    bincode::serialize_into(&f, &public_key)?;

    Ok(())
}

#[derive(serde::Deserialize, Debug)]
struct GroupJson {
    threshold: String,
    #[serde(rename = "blsKeys")]
    bls_pubkeys: Vec<String>,
}

#[derive(serde::Serialize, Debug)]
struct OutputJson {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "publicPolynomial")]
    public_polynomial: String,
    #[serde(rename = "share")]
    share: String,
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
    let group: GroupJson = serde_json::from_reader(group_file)?;

    let nodes = group
        .bls_pubkeys
        .into_iter()
        .filter(|pubkey| pubkey.len() > 2)
        .enumerate()
        .map(|(i, pubkey)| {
            // TODO: This assumes that the first 2 characters of the string will be "0x"
            let pubkey = hex::decode(&pubkey[2..])?;
            let pubkey: C::Point = bincode::deserialize(&pubkey)?;
            Ok(Node::<C>::new(i as Idx, pubkey))
        })
        .collect::<CLIResult<_>>()?;

    let group = Group {
        threshold: group
            .threshold
            .parse()
            .expect("threshold was not an integer"),
        nodes,
    };

    let phase0 = Phase0::new(pk, group, opts.publish_all)?;

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
    let shares: Vec<BundledShares<C>> = parse_bundle(&opts.input)?;

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
    let responses: Vec<BundledResponses> = parse_bundle(&opts.input)?;

    // writes the justifications to the board
    let mut board = File::create(opts.output)?;
    let output = phase2.run(&mut board, &responses)?;

    let output_file = File::create(opts.out_phase)?;
    match output {
        Phase2Result::Output(out) => {
            println!("Success. Your share and threshold pubkey are written to the output.");
            write_output(&output_file, &out)?;
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
    let phase3: Phase3<C> = bincode::deserialize_from(phase3_file)?;
    let justifications: Vec<BundledJustification<C>> = parse_bundle(&opts.input)?;

    // dummy writer instance with `vec!`
    match phase3.run(&mut vec![], &justifications) {
        Ok(out) => {
            println!("Success. Your share and threshold pubkey are written to the output.");
            let output_file = File::create(opts.output)?;
            write_output(&output_file, &out)?;
        }
        Err(err) => {
            eprintln!("DKG failed: {}", err);
        }
    };

    Ok(())
}

fn parse_bundle<D: serde::de::DeserializeOwned>(path: &str) -> CLIResult<Vec<D>> {
    let data: String = std::fs::read_to_string(path)?;
    let data: Vec<String> = serde_json::from_str(&data)?;
    data.into_iter()
        .filter(|bundle| bundle.len() > 2)
        .map(|bundle| {
            let bundle = hex::decode(&bundle[2..])?;
            let bundle: D = bincode::deserialize(&bundle)?;
            Ok(bundle)
        })
        .collect()
}

fn write_output<C: Curve, W: Write>(writer: W, out: &DKGOutput<C>) -> CLIResult<()> {
    let output = OutputJson {
        public_key: hex::encode(&bincode::serialize(&out.public.public_key())?),
        public_polynomial: hex::encode(&bincode::serialize(&out.public)?),
        share: hex::encode(&bincode::serialize(&out.share)?),
    };
    serde_json::to_writer(writer, &output)?;
    Ok(())
}
