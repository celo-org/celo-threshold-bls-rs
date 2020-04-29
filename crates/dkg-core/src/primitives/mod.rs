/// Primitives for grouping together vectors of nodes with an associated threshold
pub mod group;

/// Core DKG logic, implemented as a state machine
pub mod states;

/// 2D binary array utilities for tracking successful (or not) participation in the DKG
mod status;

use thiserror::Error;
use threshold_bls::{ecies::EciesError, poly::Idx};

/// The minimum allowed threshold is 51%
pub fn minimum_threshold(n: usize) -> usize {
    (((n as f64) / 2.0) + 1.0) as usize
}

/// The default threshold is 66%
pub fn default_threshold(n: usize) -> usize {
    (((n as f64) * 2.0 / 3.0) + 1.0) as usize
}

/// Result type alias which returns `DKGError`
pub type DKGResult<A> = Result<A, DKGError>;

#[derive(Debug, Error)]
/// Errors which may occur during the DKG
pub enum DKGError {
    /// PublicKeyNotFound is raised when the private key given to the DKG init
    /// function does not yield a public key that is included in the group.
    #[error("public key not found in list of participants")]
    PublicKeyNotFound,

    /// InvalidThreshold is raised when creating a group and specifying an
    /// invalid threshold. Either the threshold is too low, inferior to
    /// what `minimum_threshold()` returns or is too large (i.e. larger than the
    /// number of nodes).
    #[error("threshold {0} is not in range [{1},{2}]")]
    InvalidThreshold(usize, usize, usize),

    /// NotEnoughValidShares is raised when the DKG has not successfully
    /// processed enough shares because they were invalid. In that case, the DKG
    /// can not continue, the protocol MUST be aborted.
    #[error("only has {0}/{1} valid shares")]
    NotEnoughValidShares(usize, usize),

    #[error("only has {0}/{1} required justifications")]
    NotEnoughJustifications(usize, usize),

    /// Rejected is raised when the participant is rejected from the final
    /// output
    #[error("this participant is rejected from the qualified set")]
    Rejected,

    /// BincodeError is raised when de(serialization) by bincode fails
    #[error("de(serialization failed: {0})")]
    BincodeError(#[from] bincode::Error),

    /// ShareError is raised when a share is being processed
    #[error(transparent)]
    ShareError(#[from] ShareError),
}

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
/// Error which may occur while processing a share in Phase 1
pub enum ShareError {
    /// InvalidCipherText returns the error raised when decrypting the encrypted
    /// share.
    #[error("[dealer: {0}] Invalid ciphertext")]
    InvalidCiphertext(Idx, EciesError),
    /// InvalidShare is raised when the share does not corresponds to the public
    /// polynomial associated.
    #[error("[dealer: {0}] Share does not match associated public polynomial")]
    InvalidShare(Idx),
    /// InvalidPublicPolynomial is raised when the public polynomial does not
    /// have the correct degree. Each public polynomial in the scheme must have
    /// a degree equals to `threshold - 1` set for the DKG protocol.
    /// The two fields are (1) the degree of the polynomial and (2) the
    /// second is the degree it should be,i.e. `threshold - 1`.
    #[error("[dealer: {0}] polynomial does not have the correct degree, got: {1}, expected {2}")]
    InvalidPublicPolynomial(Idx, usize, usize),
}
