use gumdrop::Options;
use std::default::Default;

#[derive(Debug, Options, Clone)]
pub struct Opts {
    help: bool,
    #[options(command)]
    pub command: Option<Command>,
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "creates a group from the provided public keys and indexes")]
    Setup(SetupOpts),
    CombineShares(CombineOpts),
    CombineResponses(CombineOpts),
    CombineJustifications(CombineOpts),
}

#[derive(Debug, Options, Clone)]
pub struct SetupOpts {
    help: bool,

    #[options(help = "the threshold of the scheme")]
    pub threshold: usize,

    #[options(help = "path to the files where the public keys/indexes of all users")]
    pub nodes: String,

    #[options(help = "path to where the group will be written")]
    pub group: String,
}

#[derive(Debug, Options, Clone)]
pub struct CombineOpts {
    help: bool,

    #[options(help = "glob for all the inputs")]
    pub input: String,

    #[options(help = "the combined output")]
    pub output: String,
}
