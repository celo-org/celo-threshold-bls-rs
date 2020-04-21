pub mod coordinator;
pub mod user;

use thiserror::Error;

pub type CLIResult<T> = std::result::Result<T, CLIError>;

#[derive(Debug, Error)]
pub enum CLIError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    GlobError(#[from] glob::GlobError),
    #[error("{0}")]
    BincodeError(#[from] bincode::Error),
    #[error("{0}")]
    NodeError(#[from] dkg_core::node::NodeError),
}
