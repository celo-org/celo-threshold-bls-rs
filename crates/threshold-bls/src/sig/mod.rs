mod blind;
pub use blind::{BlindError, Token};

// Public so that the `BLSScheme` bound rustc names when a scheme family is
// implemented outside this crate is a path the implementor can actually import:
// while this was private, the suggestion was `sig::bls::common::BLSScheme`, and
// following it produced E0603. Hidden because the module is machinery, not API.
#[doc(hidden)]
pub mod bls;
pub use bls::{BLSError, G1Scheme, G2Scheme};

mod tblind;
pub use tblind::BlindThresholdError;

mod tbls;
pub use tbls::{Share, ThresholdError};

#[allow(clippy::module_inception)]
mod sig;
pub use sig::*;
