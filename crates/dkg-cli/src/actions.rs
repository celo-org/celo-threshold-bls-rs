use crate::{
    dkg_contract::{DKG as DKGContract, DKG_ABI},
    opts::*,
};
use rand::{CryptoRng, RngCore};
use std::{fs::File, io::Write, sync::Arc, time::Duration};

use dkg_core::{
    primitives::{joint_feldman::*, resharing::RDKG, *},
    DKGPhase, Phase2Result,
};

use anyhow::Result;
use ethers::prelude::*;
use ethers::providers::Middleware;
use ethers::signers::LocalWallet;
use rustc_hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use threshold_bls::{group::Curve, sig::Scheme};
use threshold_bls::{
    poly::{Idx, PublicPoly},
    sig::Share,
};

/// Target chain ID
/// TODO: move it to config
pub const CHAIN_ID: u32 = 128123;
/// Polling interval
/// TODO: move it to config
pub const INTERVAL_MS: u64 = 1000;

#[derive(Serialize, Deserialize, Debug)]
struct KeypairJson {
    address: Address,
    #[serde(rename = "privateKey")]
    private_key: String,
}

pub fn keygen<R>(opts: KeygenOpts, rng: &mut R) -> Result<()>
where
    R: CryptoRng + RngCore,
{
    let wallet = Wallet::new(rng);
    let output = KeypairJson {
        private_key: hex::encode(wallet.signer().to_bytes()),
        address: wallet.address(),
    };

    if let Some(path) = opts.path {
        let f = File::create(path)?;
        serde_json::to_writer(&f, &output)?;
    } else {
        serde_json::to_writer(std::io::stdout(), &output)?;
    }

    Ok(())
}

pub async fn deploy(opts: DeployOpts) -> Result<()> {
    // hard-code the contract's bytecode when deploying
    let bytecode = include_str!["../dkg.bin"];
    let bytecode = bytecode.from_hex::<Vec<u8>>()?;

    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?
        .interval(Duration::from_millis(INTERVAL_MS));
    let wallet = opts
        .private_key
        .parse::<LocalWallet>()?
        .with_chain_id(CHAIN_ID);
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let abi = DKG_ABI.clone();

    let factory = ContractFactory::new(abi, Bytes::from(bytecode), client);
    let contract = factory
        .deploy((opts.threshold as u64, opts.phase_duration as u64))?
        .send()
        .await?;

    println!("Contract deployed at: {:?}", contract.address());
    Ok(())
}

pub async fn allow(opts: AllowlistOpts) -> Result<()> {
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?
        .interval(Duration::from_millis(INTERVAL_MS));
    let wallet = opts
        .private_key
        .parse::<LocalWallet>()?
        .with_chain_id(CHAIN_ID);
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let contract = DKGContract::new(opts.contract_address, client);

    for addr in opts.address {
        let tx = contract.allowlist(addr).block(BlockNumber::Pending);
        let tx = tx.send().await?.await?;
        println!("Sent `allow` tx for {:?} (hash: {:?})", addr, tx);
    }

    Ok(())
}

pub async fn start(opts: StartOpts) -> Result<()> {
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?
        .interval(Duration::from_millis(INTERVAL_MS));
    let wallet = opts
        .private_key
        .parse::<LocalWallet>()?
        .with_chain_id(CHAIN_ID);
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);
    let contract = DKGContract::new(opts.contract_address, client);

    // Submit the tx and wait for the confirmation
    let _tx_hash = contract.start().send().await?.await?;

    Ok(())
}

pub async fn reshare<S, M, C, R>(opts: ReshareConfig, rng: &mut R) -> Result<()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    M: Middleware,
    R: RngCore,
{
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?
        .interval(Duration::from_millis(INTERVAL_MS));
    let wallet = opts
        .private_key
        .parse::<LocalWallet>()?
        .with_chain_id(CHAIN_ID);
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    // we need the previous group and public poly for resharing
    let previous_group = {
        let previous_dkg = DKGContract::new(opts.previous_contract_address, client.clone());
        let previous_group = previous_dkg.get_bls_keys().call().await?;
        pubkeys_to_group::<C>(previous_group)?
    };

    let public_poly = opts.public_polynomial.from_hex::<Vec<u8>>()?;
    let public_poly: PublicPoly<C> = bincode::deserialize(&public_poly)?;

    let dkg = DKGContract::new(opts.contract_address, client.clone());

    let (private_key, public_key) = S::keypair(rng);

    register::<S, Provider<Http>, LocalWallet>(&dkg, &public_key).await?;
    let new_group = get_group::<C, Provider<Http>, LocalWallet>(&dkg).await?;

    let phase0 = if let Some(share) = opts.share {
        let share = share.from_hex::<Vec<u8>>()?;
        let share: Share<C::Scalar> = bincode::deserialize(&share)?;
        let dkg_output = DKGOutput {
            share,
            qual: previous_group,
            public: public_poly,
        };
        RDKG::new_from_share(private_key, dkg_output, new_group)
    } else {
        RDKG::new_member(private_key, previous_group, public_poly, new_group)
    }?;

    run_dkg(dkg, phase0, rng, opts.output_path).await
}

pub async fn run<S, C, R>(opts: DKGConfig, rng: &mut R) -> Result<()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    R: RngCore,
{
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?
        .interval(Duration::from_millis(INTERVAL_MS));
    let wallet = opts
        .private_key
        .parse::<LocalWallet>()?
        .with_chain_id(CHAIN_ID);
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let dkg = DKGContract::new(opts.contract_address, client);

    // 1. Generate the keys
    let (private_key, public_key) = S::keypair(rng);

    // 2. Register
    register::<S, Provider<Http>, LocalWallet>(&dkg, &public_key).await?;

    // Get the group info
    let group = get_group::<C, Provider<Http>, LocalWallet>(&dkg).await?;
    let phase0 = DKG::new(private_key, group)?;

    run_dkg(dkg, phase0, rng, opts.output_path).await
}

async fn register<S: Scheme, M: Middleware + 'static, Z: Signer + 'static>(
    dkg: &DKGContract<SignerMiddleware<M, Z>>,
    public_key: &S::Public,
) -> Result<()> {
    println!("Registering...");
    let public_key_serialized = bincode::serialize(public_key)?;
    let public_key_bytes = ethers::prelude::Bytes::from(public_key_serialized);
    let _pending_tx = dkg.register(public_key_bytes).send().await?.await?;

    // Wait for Phase 1
    wait_for_phase(dkg, 1).await?;

    Ok(())
}

async fn get_group<C: Curve, M: Middleware + 'static, Z: Signer + 'static>(
    dkg: &DKGContract<SignerMiddleware<M, Z>>,
) -> Result<Group<C>> {
    let group = dkg.get_bls_keys().call().await?;
    let participants = dkg.get_participants().call().await?;
    confirm_group(&group, participants)?;

    let group = pubkeys_to_group::<C>(group)?;
    Ok(group)
}

fn confirm_group(
    pubkeys: &(U256, Vec<ethers::prelude::Bytes>),
    participants: Vec<Address>,
) -> Result<()> {
    // print some debug info
    println!(
        "Will run DKG with the group listed below and threshold {}",
        pubkeys.0
    );
    for (bls_pubkey, address) in pubkeys.1.iter().zip(&participants) {
        let key = bls_pubkey.to_vec().to_hex::<String>();
        println!("{:?} -> {}", address, key)
    }

    if !clt::confirm(
        "\nDoes the above group look good to you?",
        false,
        "\n",
        true,
    ) {
        return Err(anyhow::anyhow!("User rejected group choice."));
    }

    Ok(())
}

// Pass the result of `get_bls_keys` to convert the raw data to a group
fn pubkeys_to_group<C: Curve>(pubkeys: (U256, Vec<ethers::prelude::Bytes>)) -> Result<Group<C>> {
    let nodes = pubkeys
        .1
        .into_iter()
        .filter(|pubkey| !pubkey.to_vec().is_empty()) // skip users that did not register
        .enumerate()
        .map(|(i, pubkey)| {
            let pubkey: C::Point = bincode::deserialize(&pubkey.to_vec()[..])?;
            Ok(Node::<C>::new(i as Idx, pubkey))
        })
        .collect::<Result<_>>()?;

    Ok(Group {
        threshold: pubkeys.0.as_u64() as usize,
        nodes,
    })
}

// Shared helper for running the DKG in both normal and re-sharing mode
async fn run_dkg<P, C, R, M: Middleware + 'static>(
    mut dkg: DKGContract<M>,
    phase0: P,
    rng: &mut R,
    output_path: Option<String>,
) -> Result<()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    // S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    P: Phase0<C>,
    R: RngCore,
{
    // Run Phase 1 and publish to the chain
    println!("Calculating and broadcasting our shares...");
    let phase1 = phase0.run(&mut dkg, rng).await?;

    // Wait for Phase 2
    wait_for_phase(&dkg, 2).await?;

    // Get the shares
    let shares = dkg.get_shares().call().await?;
    println!("Got {} shares...", shares.len());
    let shares = parse_bundle(&shares)?;
    println!("Parsed {} shares. Running Phase 2", shares.len());

    let phase2 = phase1.run(&mut dkg, &shares).await?;

    // Get the responses
    let responses = dkg.get_responses().call().await?;
    println!("Got {} responses...", responses.len());
    let responses = parse_bundle(&responses)?;
    println!("Parsed the responses. Getting result.");

    // Run Phase 2
    let result = match phase2.run(&mut dkg, &responses).await? {
        Phase2Result::Output(out) => Ok(out),
        // Run Phase 3 if Phase 2 errored
        Phase2Result::GoToPhase3(phase3) => {
            println!("There were complaints. Running Phase 3.");
            wait_for_phase(&dkg, 3).await?;

            let justifications = dkg.get_justifications().call().await?;
            let justifications = parse_bundle(&justifications)?;

            phase3.run(&mut dkg, &justifications).await
        }
    };

    match result {
        Ok(output) => {
            println!("Success. Your share and threshold pubkey are ready.");
            if let Some(path) = output_path {
                let file = File::create(path)?;
                write_output(&file, &output)?;
            } else {
                write_output(std::io::stdout(), &output)?;
            }
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!("DKG error: {}", err)),
    }
}

#[derive(serde::Serialize, Debug)]
struct OutputJson {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "publicPolynomial")]
    public_polynomial: String,
    #[serde(rename = "share")]
    share: String,
}

async fn wait_for_phase<M: Middleware>(
    dkg: &DKGContract<M>,
    num: u64,
) -> Result<(), ContractError<M>> {
    println!("Waiting for Phase {} to start", num);

    loop {
        let phase = dkg.in_phase().call().await?;
        if phase.as_u64() == num {
            break;
        }
        print!(".");
        tokio::time::sleep(std::time::Duration::from_millis(INTERVAL_MS)).await;
    }

    println!("\nIn Phase {}. Moving to the next step.", num);

    Ok(())
}

fn parse_bundle<D: serde::de::DeserializeOwned>(
    bundle: &[ethers::prelude::Bytes],
) -> Result<Vec<D>> {
    bundle
        .iter()
        .filter(|item| !item.to_vec().is_empty()) // filter out empty items
        .map(|item| Ok(bincode::deserialize::<D>(&item.to_vec()[..])?))
        .collect()
}

fn write_output<C: Curve, W: Write>(writer: W, out: &DKGOutput<C>) -> Result<()> {
    let output = OutputJson {
        public_key: hex::encode(bincode::serialize(&out.public.public_key())?),
        public_polynomial: hex::encode(bincode::serialize(&out.public)?),
        share: hex::encode(bincode::serialize(&out.share)?),
    };
    serde_json::to_writer(writer, &output)?;
    Ok(())
}
