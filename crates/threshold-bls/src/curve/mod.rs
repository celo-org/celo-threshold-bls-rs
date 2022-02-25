/// Wrappers around the BLS12-381 curve from the [paired](http://docs.rs/paired) crate
#[cfg(feature = "bls12_381")]
pub mod bls12381;

/// Wrappers around the BLS12-377 curve from [zexe](https://github.com/scipr-lab/zexe/tree/master/algebra/src/bls12_377)
//#[cfg(feature = "bls12_377")]
pub mod zexe;

use thiserror::Error;

/// Error which unifies all curve specific errors from different libraries
#[derive(Debug, Error)]
pub enum CurveError {
//    #[cfg(feature = "bls12_377")]
    #[error("Zexe Error: {0}")]
    BLS12_377(zexe::ZexeError),

//    #[cfg(feature = "bls12_381")]
//    #[error("Bellman Error: {0}")]
//    BLS12_381(bls12381::BellmanError),
}
