#[cfg(feature = "bls12_381")]
pub mod bls12381;

#[cfg(feature = "bls12_377")]
pub mod zexe;

use thiserror::Error;

/// Error which unifies all curve specific errors from different libraries
#[derive(Debug, Error)]
pub enum CurveError {
    #[cfg(feature = "bls12_377")]
    #[error("Zexe Error: {0}")]
    BLS12_377(zexe::ZexeError),

    #[cfg(feature = "bls12_381")]
    #[error("Bellman Error: {0}")]
    BLS12_381(bls12381::BellmanError),
}
