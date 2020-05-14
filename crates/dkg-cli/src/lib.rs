pub mod coordinator;
pub mod user;

use thiserror::Error;

pub type CLIResult<T> = std::result::Result<T, CLIError>;

#[derive(Debug, Error)]
pub enum CLIError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    GlobError(#[from] glob::GlobError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error(transparent)]
    NodeError(#[from] dkg_core::node::NodeError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
}
