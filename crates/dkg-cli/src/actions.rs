use crate::{
    dkg_contract::{DKG as DKGContract, DKG_ABI},
    opts::*,
};
use rand::RngCore;
use std::{fs::File, io::Write};

use dkg_core::{
    primitives::{joint_feldman::*, *},
    DKGPhase, Phase2Result,
};

use anyhow::Result;
use ethers::prelude::*;
use rustc_hex::{FromHex, ToHex};
use std::convert::TryFrom;

use threshold_bls::poly::Idx;
use threshold_bls::{group::Curve, sig::Scheme};

#[derive(serde::Serialize, Debug)]
struct CeloKeypairJson {
    address: Address,
    #[serde(rename = "privateKey")]
    private_key: String,
}

pub fn keygen<R>(opts: KeygenOpts, rng: &mut R) -> Result<()>
where
    R: RngCore,
{
    let wallet = Wallet::new(rng);
    let output = CeloKeypairJson {
        private_key: hex::encode(bincode::serialize(wallet.private_key())?),
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

    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?;
    let client = opts.private_key.parse::<Wallet>()?.connect(provider);
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
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?;
    let client = opts.private_key.parse::<Wallet>()?.connect(provider);

    let contract = DKGContract::new(opts.contract_address, client);

    let mut tx_futs = Vec::new();
    for addr in opts.address {
        let tx = contract
            .allowlist(addr)
            .block(BlockNumber::Pending)
            .send()
            .await?;
        println!("Sent `allow` tx for {:?} (hash: {:?})", addr, tx);
        tx_futs.push(contract.client().pending_transaction(tx));
    }

    // Await them all
    futures::future::join_all(tx_futs).await;

    Ok(())
}

pub async fn start(opts: StartOpts) -> Result<()> {
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?;
    let client = opts.private_key.parse::<Wallet>()?.connect(provider);

    let contract = DKGContract::new(opts.contract_address, client);

    // Submit the tx and wait for the confirmation
    let tx_hash = contract.start().send().await?;
    let _tx_receipt = contract.client().pending_transaction(tx_hash).await?;

    Ok(())
}

pub async fn run<S, C, R>(opts: DKGConfig, rng: &mut R) -> Result<()>
where
    C: Curve,
    // We need to bind the Curve's Point and Scalars to the Scheme
    S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
    R: RngCore,
{
    let provider = Provider::<Http>::try_from(opts.node_url.as_str())?;
    let client = opts.private_key.parse::<Wallet>()?.connect(provider);
    let dkg = DKGContract::new(opts.contract_address, client);

    // 1. Generate the keys
    let (private_key, public_key) = S::keypair(rng);

    // 2. Register
    println!("Registering...");
    let public_key_serialized = bincode::serialize(&public_key)?;
    let pending_tx = dkg.register(public_key_serialized).send().await?;
    let _tx_receipt = dkg.pending_transaction(pending_tx).await?;

    // Wait for Phase 1
    wait_for_phase(&dkg, 1).await?;

    // Get the group info
    let group = dkg.get_bls_keys().call().await?;
    let participants = dkg.get_participants().call().await?;

    // print some debug info
    println!(
        "Will run DKG with the group listed below and threshold {}",
        group.0
    );
    for (bls_pubkey, address) in group.1.iter().zip(&participants) {
        let key = bls_pubkey.to_hex::<String>();
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

    let nodes = group
        .1
        .into_iter()
        .filter(|pubkey| !pubkey.is_empty()) // skip users that did not register
        .enumerate()
        .map(|(i, pubkey)| {
            let pubkey: C::Point = bincode::deserialize(&pubkey)?;
            Ok(Node::<C>::new(i as Idx, pubkey))
        })
        .collect::<Result<_>>()?;

    let group = Group {
        threshold: group.0.as_u64() as usize,
        nodes,
    };

    // Instantiate the DKG with the group info
    let phase0 = DKG::new(private_key, group)?;

    run_dkg(dkg, phase0, rng, opts.output_path).await
}

// Shared helper for running the DKG in both normal and re-sharing mode
async fn run_dkg<P, C, R>(
    mut dkg: DKGContract<Http, Wallet>,
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

async fn wait_for_phase<P: JsonRpcClient, S: Signer>(
    dkg: &DKGContract<P, S>,
    num: u64,
) -> Result<(), ContractError> {
    println!("Waiting for Phase {} to start", num);

    loop {
        let phase = dkg.in_phase().call().await?;
        if phase.as_u64() == num {
            break;
        }
        print!(".");
        // 6s for 1 Celo block
        tokio::time::delay_for(std::time::Duration::from_millis(6000)).await;
    }

    println!("\nIn Phase {}. Moving to the next step.", num);

    Ok(())
}

fn parse_bundle<D: serde::de::DeserializeOwned>(bundle: &[Vec<u8>]) -> Result<Vec<D>> {
    bundle
        .iter()
        .filter(|item| !item.is_empty()) // filter out empty items
        .map(|item| Ok(bincode::deserialize::<D>(&item)?))
        .collect()
}

fn write_output<C: Curve, W: Write>(writer: W, out: &DKGOutput<C>) -> Result<()> {
    let output = OutputJson {
        public_key: hex::encode(&bincode::serialize(&out.public.public_key())?),
        public_polynomial: hex::encode(&bincode::serialize(&out.public)?),
        share: hex::encode(&bincode::serialize(&out.share)?),
    };
    serde_json::to_writer(writer, &output)?;
    Ok(())
}
