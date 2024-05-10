use ethers::types::Address;
use gumdrop::Options;
use std::default::Default;

#[derive(Debug, Options, Clone)]
pub struct DKGOpts {
    help: bool,
    #[options(command)]
    pub command: Option<Command>,
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "creates a new keypair which you must fund to participate in the DKG")]
    Keygen(KeygenOpts),

    #[options(help = "runs the DKG and produces your share")]
    Run(DKGConfig),

    #[options(help = "runs the DKG and produces your share")]
    Reshare(ReshareConfig),

    #[options(help = "deploy the DKG smart contract")]
    Deploy(DeployOpts),

    #[options(help = "start the DKG")]
    Start(StartOpts),

    #[options(help = "allow 1 or more DKG participants")]
    Allow(AllowlistOpts),
}

#[derive(Debug, Options, Clone)]
pub struct KeygenOpts {
    help: bool,

    #[options(help = "path to the file where the keys will be written (stdout if none provided)")]
    pub path: Option<String>,
}

#[derive(Debug, Options, Clone)]
pub struct DKGConfig {
    help: bool,

    #[options(help = "the RPC node's endpoint")]
    pub node_url: String,

    #[options(
        help = "path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)"
    )]
    pub private_key: String,

    #[options(help = "the DKG contract's address")]
    pub contract_address: Address,

    #[options(
        help = "the path where the result of the DKG will be stored (stdout if none provided)"
    )]
    pub output_path: Option<String>,
}

#[derive(Debug, Options, Clone)]
pub struct ReshareConfig {
    help: bool,

    #[options(help = "the RPC node's endpoint")]
    pub node_url: String,

    #[options(
        help = "path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)"
    )]
    pub private_key: String,

    #[options(help = "the DKG resharing contract's address")]
    pub contract_address: Address,

    #[options(
        help = "the path where the result of the DKG will be stored (stdout if none provided)"
    )]
    pub output_path: Option<String>,

    #[options(
        help = "your BLS share which was produced from the last DKG round (skip this argument if you do not have one)"
    )]
    pub share: Option<String>,

    #[options(
        help = "the address of the previous DKG contract (used to fetch the previous group's information)"
    )]
    pub previous_contract_address: Address,

    #[options(help = "the public polynomial which was produced in the previous DKG")]
    pub public_polynomial: String,
}

#[derive(Debug, Options, Clone)]
pub struct DeployOpts {
    help: bool,

    #[options(help = "the RPC node's endpoint", default = "")]
    pub node_url: String,

    #[options(
        help = "path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)"
    )]
    pub private_key: String,

    #[options(help = "the minimum number of DKG participants required")]
    pub threshold: usize,

    #[options(help = "the number of blocks per phase")]
    pub phase_duration: usize,
}

#[derive(Debug, Options, Clone)]
pub struct StartOpts {
    help: bool,

    #[options(help = "node's RPC endpoint")]
    pub node_url: String,

    #[options(
        help = "path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)"
    )]
    pub private_key: String,

    #[options(help = "the DKG contract's address")]
    pub contract_address: Address,
}

#[derive(Debug, Options, Clone)]
pub struct AllowlistOpts {
    help: bool,

    #[options(help = "the RPC node's endpoint")]
    pub node_url: String,

    #[options(
        help = "path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)"
    )]
    pub private_key: String,

    #[options(help = "the addresses to allow for the DKG")]
    pub address: Vec<Address>,

    #[options(help = "the DKG contract's address")]
    pub contract_address: Address,
}
