//! This module holds the curve to use for the example. One can switch the curve
//! by changing the exported type `Curve`.
//! For example, to use `bls12-381` instead, one can import
//! ```
//! pub use threshold::curve::bls12381::PairingCurve;
//! ```
pub use threshold::curve::zexe::{G2Curve, PairingCurve as Pairing};
use threshold::group::Curve;
use threshold::sig::tblind::G2Scheme;

pub type KeyCurve = G2Curve;
pub type PrivateKey = <KeyCurve as Curve>::Scalar;
pub type PublicKey = <KeyCurve as Curve>::Point;
pub type Scheme = G2Scheme<Pairing>;
