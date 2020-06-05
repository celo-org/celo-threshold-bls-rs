/// Primitives for grouping together vectors of nodes with an associated threshold
pub(crate) mod group;
pub use group::*;

pub(crate) mod phases;
pub use phases::*;

pub(crate) mod types;
pub use types::*;

/// 2D binary array utilities for tracking successful (or not) participation in the DKG
pub(crate) mod status;

pub mod joint_feldman;

pub mod resharing;

mod common;

mod errors;
pub use errors::{DKGError, DKGResult, ShareError};

/// The minimum allowed threshold is 51%
pub fn minimum_threshold(n: usize) -> usize {
    (((n as f64) / 2.0) + 1.0) as usize
}

/// The default threshold is 66%
#[allow(dead_code)]
pub(crate) fn default_threshold(n: usize) -> usize {
    (((n as f64) * 2.0 / 3.0) + 1.0) as usize
}
