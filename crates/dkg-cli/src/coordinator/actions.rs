use super::opts::{CombineOpts, SetupOpts};
use anyhow::Result;

use dkg_core::{
    primitives::{Group, Node},
    NodeError,
};
use threshold_bls::{group::Curve, poly::Idx, sig::Scheme};

use glob::glob;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::File;

/// Reads the initial pubkey/index pairs per participant, and creates the group
pub fn setup<C, S>(opts: SetupOpts) -> Result<()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
{
    let mut nodes = Vec::new();

    for path in glob(&opts.nodes).expect("Failed to read glob pattern") {
        let file = File::open(path?)?;

        let index: Idx = bincode::deserialize_from(&file)?;
        let pubkey: S::Public = bincode::deserialize_from(&file)?;

        let node = Node::<C>::new(index, pubkey);
        nodes.push(node);
    }

    // generate the group
    let group = Group::new(nodes, opts.threshold).map_err(NodeError::DKGError)?;
    // ...and write it to a file
    let f = File::create(opts.group)?;
    bincode::serialize_into(f, &group)?;

    Ok(())
}

/// Combines the contributions of each participant for the next phase
pub fn combine<T: DeserializeOwned + Serialize>(opts: CombineOpts) -> Result<()> {
    let mut data: Vec<T> = Vec::new();

    for path in glob(&opts.input).expect("Failed to read glob pattern") {
        let file = File::open(path?)?;
        if let Ok(de) = bincode::deserialize_from(&file) {
            data.push(de);
        }
    }

    let file = File::create(opts.output)?;
    bincode::serialize_into(file, &data)?;

    Ok(())
}
