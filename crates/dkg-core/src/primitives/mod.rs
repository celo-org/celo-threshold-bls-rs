pub mod group;
pub mod states;
mod status;

use std::fmt;
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

#[derive(Debug, PartialEq, Error)]
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

    /// Rejected is thrown when the participant is rejected from the final
    /// output
    #[error("this participant is rejected from the qualified set")]
    Rejected,
}

// TODO: potentially add to the API the ability to streamline the decryption of
// bundles, and in that case, it would make sense to report those errors.
#[derive(Debug)]
struct ShareError {
    // XXX better structure to put dealer_idx in an outmost struct but leads to
    // more verbose code. To review?
    dealer_idx: Idx,
    error: ShareErrorType,
}

impl fmt::Display for ShareError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ShareError(dealer: {}): {}", self.dealer_idx, self.error)
    }
}

impl ShareError {
    fn from(dealer_idx: Idx, error: ShareErrorType) -> Self {
        Self { dealer_idx, error }
    }
}

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
enum ShareErrorType {
    /// InvalidCipherText returns the error raised when decrypting the encrypted
    /// share.
    #[error("Invalid ciphertext")]
    InvalidCiphertext(EciesError),
    /// InvalidShare is raised when the share does not corresponds to the public
    /// polynomial associated.
    #[error("Share does not match associated public polynomial")]
    InvalidShare,
    /// InvalidPublicPolynomial is raised when the public polynomial does not
    /// have the correct degree. Each public polynomial in the scheme must have
    /// a degree equals to `threshold - 1` set for the DKG protocol.
    /// The two fields are (1) the degree of the polynomial and (2) the
    /// second is the degree it should be,i.e. `threshold - 1`.
    #[error("polynomial does not have the correct degree, got: {0}, expected {1}")]
    InvalidPublicPolynomial(usize, usize),
}
