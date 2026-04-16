/// Wrappers around the BLS12-377 curve from [zexe](https://github.com/scipr-lab/zexe/tree/master/algebra/src/bls12_377)
pub mod bls12377;

use thiserror::Error;

/// Error which unifies all curve specific errors from different libraries
#[derive(Debug, Error)]
pub enum CurveError {
    #[error("Zexe Error: {0}")]
    BLS12_377(bls12377::ZexeError),
}
