# Distributed Key Generation CLI

This crate provides a CLI to the provided DKG. 

As explained in [`dkg-core`](../dkg-core), there are a few phases. For each phase, users perform some computation which is then published to a "board". An authenticated channel is assumed for publishing to the board. In this CLI, the board is assumed to be a smart contract on a EVM compatible chain. Before advancing to each of the next phases, the board gathers all participants' contributions and combines them in a data structure which gets downloaded from the chain. These contributions are then used by each participant in the next round.

## Participating in the DKG

Prerequisite: Building this binary requires having `Solc@0.6.6` available in your PATH. 
That can be done either by [installing the binary](https://github.com/ethereum/solidity/releases/tag/v0.6.6)
or using [`solc-select`](https://github.com/crytic/solc-select). Other methods can also be found
in the [Solidity docs](https://solidity.readthedocs.io/en/latest/installing-solidity.html).


Install the DKG CLI with `cargo build --release`. 
We will use the Alfajores testnet for this example, which you can access by using `https://alfajores-forno.celo-testnet.org` as a `NODE_URL`. You can fund your account by inserting your `address` to the [Alfajores faucet](https://celo.org/developers/faucet).

1. `dkg-cli keygen --path ./keypair` 

This will generate your keypair. You should then fund the `address` with some tokens 
to pay for transaction fees and send it to the DKG deployer, so that they allow 
you to participate in the DKG.

2. `dkg-cli run --node-url $NODE_URL -p $PRIVATE_KEY --contract-address $DKG_ADDRESS -o ./output`

Then you can leave the terminal open until completion. It will run the DKG and output
the shares and threshold public key at the `output` file in json format.

Example of successful output:

```
Success. Your share and threshold pubkey are ready.
{"publicKey":"610f3c6dc58565e14d50fddfacf76d345fd8a792b3b876a75607e61b4c218930a76ed4e7685bde19989e8993552b330138e1a045cb53999a1aa42fbf736f4c7a707aead407d06dce7fa122b71d1c49d63a852fac5cfa8f8c5b96b07d98838900","publicPolynomial":"0300000000000000610f3c6dc58565e14d50fddfacf76d345fd8a792b3b876a75607e61b4c218930a76ed4e7685bde19989e8993552b330138e1a045cb53999a1aa42fbf736f4c7a707aead407d06dce7fa122b71d1c49d63a852fac5cfa8f8c5b96b07d988389003ffc28520c47483944c60d65939f0092560e7a5a7d3365e3be2db5f89753779c8445cfdcbad1d79e315766667888a4004d61db1530a94d22c60647e29ae10ab7f79d65a457bc1c66932565300922d1c72026856d9192433e4af5ff12ea8e200141b576717d4dde36c6f5975e1fcb9b14c5a6296c320868b273ab2261a69f57f4fd6b3588a917a5989a9f74d791c61c0148ba5b592c2a4e7667c45808472625a6f5397ba8ffb9cf75f76828203441ed3880dde594b15cd76bd918b6e024924300","share":"010000000ae74d765e992466c3df2ba76348c1ad892f4ee41bf53bf76ead05b06bdadd10"}
```

## Commands

### Keypair generation

```
Usage: dkg-cli keygen [OPTIONS]

Optional arguments:
  -h, --help
  -p, --path PATH  path to the file where the keys will be written (stdout if none provided)
```

### Running the DKG

```
Usage: dkg-cli run [OPTIONS]

Optional arguments:
  -h, --help
  -n, --node-url NODE-URL  the RPC node's endpoint
  -p, --private-key PRIVATE-KEY
                           path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)
  -c, --contract-address CONTRACT-ADDRESS
                           the DKG contract's address
  -o, --output-path OUTPUT-PATH
                           the path where the resulting of the DKG will be stored (stdout if none provided)
```

### Resharing

After a DKG deal has been done, you may want to add or remove members from the group.
This is done via the re-sharing command. If you are a member that has already participated
in a previous round of the DKG, you must pass the `share` parameter. If you are a new member,
you should specify the threshold polynomial which was generated in the previous round (you can get
that from any of the previous members)


```
Usage: dkg-cli reshare [OPTIONS]

Optional arguments:
  -h, --help
  -n, --node-url NODE-URL  the RPC node's endpoint
  -p, --private-key PRIVATE-KEY
                           path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)
  -c, --contract-address CONTRACT-ADDRESS
                           the DKG resharing contract's address
  -o, --output-path OUTPUT-PATH
                           the path where the result of the DKG will be stored (stdout if none provided)
  -s, --share SHARE        your BLS share which was produced from the last DKG round (skip this argument if you do not have one)
  -P, --previous-contract-address PREVIOUS-CONTRACT-ADDRESS
                           the address of the previous DKG contract (used to fetch the previous group's information)
  --public-polynomial PUBLIC-POLYNOMIAL
                           the public polynomial which was produced in the previous DKG
```

### Deploying the contract

```
Usage: dkg-cli deploy [OPTIONS]

Optional arguments:
  -h, --help
  -n, --node-url NODE-URL    the RPC node's endpoint
  -p, --private-key PRIVATE-KEY
                             path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)
  -t, --threshold THRESHOLD  the minimum number of DKG participants required
  -P, --phase-duration PHASE-DURATION
                             the number of blocks per phase

```

### Allowing DKG participants to join the DKG

```
Usage: dkg-cli allow [OPTIONS]

Optional arguments:
  -h, --help
  -n, --node-url NODE-URL  the RPC node's endpoint
  -p, --private-key PRIVATE-KEY
                           path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)
  -a, --address ADDRESS    the addresses to allow for the DKG
  -c, --contract-address CONTRACT-ADDRESS
                           the DKG contract's address
```

_Note: Multiple `-a` arguments can be passed in order to allow multiple participants in 1 call_

### Starting the DKG

```
Usage: dkg-cli start [OPTIONS]

Optional arguments:
  -h, --help
  -n, --node-url NODE-URL  the RPC node's endpoint
  -p, --private-key PRIVATE-KEY
                           path to your private key (hint: use the `keygen` command to generate a new one if you don't have one)
  -c, --contract-address CONTRACT-ADDRESS
                           the DKG contract's address
```

## Using Docker

A docker image of the CLI can be used instead via `docker run -ti ghcr.io/m-kus/dkg-cli`

NOTE: Docker is tricky to install on recent Fedora, but Podman works fine. The only changes needed are changing docker to podman, and adding a parameter to override SELinux for the mount: `podman run -ti --security-opt label=disable -v $PWD:/dkg ghcr.io/m-kus/dkg-cli`.
