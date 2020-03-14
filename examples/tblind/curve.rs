//! This module holds the curve to use for the example. One can switch the curve
//! by changing the exported type `Curve`.
//! For example, to use `bls12-381` instead, one can import
//! ```
//! pub use threshold::curve::bls12381::PairingCurve;
//! ```
pub use threshold::curve::zexe::{G2Curve, PairingCurve as Pairing};

pub type KeyCurve = G2Curve;
