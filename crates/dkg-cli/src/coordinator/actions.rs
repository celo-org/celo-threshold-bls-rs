use super::opts::{CombineOpts, SetupOpts};
use dkg_core::primitives::{Group, Node};
use threshold_bls::{
    group::{Curve, Point},
    sig::Scheme,
    Index,
};

use glob::glob;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::File;

/// Reads the initial pubkey/index pairs per participant, and creates the group
pub fn setup<C, S>(opts: SetupOpts) -> Result<(), ()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    <C as Curve>::Point: Point<S::Private>,
    <S as Scheme>::Signature: Point<<C as Curve>::Scalar>,
{
    let files = glob(&opts.nodes).expect("Failed to read glob pattern");

    let paths = files.map(|res| res.expect("invalid path"));

    let nodes = paths
        .map(|path| {
            let file = File::open(path).expect("could not open path");
            let index: Index = bincode::deserialize_from(&file).unwrap();
            let pubkey: S::Public = bincode::deserialize_from(&file).unwrap();
            Node::<C>::new(index, pubkey)
        })
        .collect::<Vec<_>>();

    // generate the group
    let group = Group::new(nodes, opts.threshold).unwrap();
    // ...and write it to a file
    let f = File::create(opts.group).unwrap();
    bincode::serialize_into(f, &group).unwrap();

    Ok(())
}

/// Combines the contributions of each participant for the next phase
pub fn combine<T: DeserializeOwned + Serialize>(opts: CombineOpts) {
    let files = glob(&opts.input).expect("Failed to read glob pattern");
    let paths = files.map(|res| res.expect("invalid path"));

    let data: Vec<T> = paths
        .map(|path| {
            let file = File::open(path).expect("could not open path");
            bincode::deserialize_from(&file).unwrap()
        })
        .collect::<Vec<_>>();

    let file = File::create(opts.output).expect("could not create path");
    bincode::serialize_into(file, &data).unwrap()
}
