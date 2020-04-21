use gumdrop::Options;
use std::default::Default;

use threshold_bls::Index;

#[derive(Debug, Options, Clone)]
pub struct DKGOpts {
    help: bool,
    #[options(command)]
    pub command: Option<Command>,
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "creates a new challenge for the ceremony")]
    New(NewOpts),

    #[options(help = "generates your shares and the next phase file")]
    PublishShares(PublishSharesOpts),

    #[options(help = "generates your responses and the next phase file")]
    PublishResponses(StateOpts),

    #[options(help = "tries to generate the shares/threshold pubkey, or prompts to go to phase 3")]
    TryFinalize(StateOpts),

    #[options(
        help = "using the justifications, it will generate the shares/threshold pubkey, or return an error"
    )]
    Finalize(FinalizeOpts),
}

#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,

    #[options(help = "your aggreed upon index in the DKG")]
    pub index: Index,

    #[options(help = "path to the file where the private key will be written")]
    pub private_key: String,

    #[options(help = "path to the file where the public key and the index will be written")]
    pub public_key: String,
}

#[derive(Debug, Options, Clone)]
pub struct PublishSharesOpts {
    help: bool,

    #[options(help = "path to the file where the private key will be written")]
    pub private_key: String,

    #[options(help = "path to the file where the public key and the index will be written")]
    pub group: String,

    #[options(help = "the file where the data for the next phase will be written")]
    pub out_phase: String,

    #[options(help = "the shares will be written to this file")]
    pub output: String,
}

#[derive(Debug, Options, Clone)]
pub struct StateOpts {
    help: bool,

    #[options(help = "the file where the data for the current phase will be read from")]
    pub in_phase: String,

    #[options(help = "the file where the data for the next phase will be written")]
    pub out_phase: String,

    #[options(help = "the input will be written read from this file")]
    pub input: String,

    #[options(help = "the output will be written to this file")]
    pub output: String,
}

#[derive(Debug, Options, Clone)]
pub struct FinalizeOpts {
    help: bool,

    #[options(help = "the file where the data for the current phase will be read from")]
    pub in_phase: String,

    #[options(help = "the input will be written read from this file")]
    pub input: String,

    #[options(help = "the output will be written to this file")]
    pub output: String,
}
