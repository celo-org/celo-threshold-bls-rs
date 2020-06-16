# Automated DKG using Ethers RS

## Client Side

The `Board` and `DKGPhase` traits were reworked to work with async. This means that
@dignifiedquire & others can implement the Board trait with their async backends such as
libp2p. In addition, this PR removes the need for using the Celo CLI by leveraging
an Ethereum Rust library I wrote called ethers, which has Celo support by augmenting
the transaction format (link to PR).

The CLI has been reworked as follows, assuming contract address at `CONTRACT_ADDRESS`.

1. `dkg keygen -p ./private-key` to generate your private key. You should then 
fund the address with some CELO to pay for tx fees. You should send the address to the
DKG deployer, so that they whitelist you.
2. `dkg run -n https://alfajores-blockscout.celo-testnet.org -p ./private-key -c $CONTRACT_ADDRESS -o ./output`

Then you can leave the terminal open until completion. It will run the DKG and output
the shares and threshold public key at the `output` file in json format.

## DKG Coordinator

### Deploying the contract

```
./dkg-cli deploy \
    -n https://alfajores-forno.celo-testnet.org \
    -p d652abb81e8c686edba621a895531b1f291289b63b5ef09a94f686a5ecdd5db1  \
    --threshold 2 \
    --phase-duration 100
```

### Whitelisting the DKG participants

```
dkg-cli whitelist 
    -n https://alfajores-forno.celo-testnet.org 
    -p d652abb81e8c686edba621a895531b1f291289b63b5ef09a94f686a5ecdd5db1 
    -c 6c3ee10ecef7eece161e225cd32ae18baa717176 
    -a d9497849edd46a04fcd256512d44458579f6abc0
    -a fad1b38aa67736d6ac74d6373081ff593e3f0bd1
```

### Starting the DKG

```
dkg-cli start
    -n https://alfajores-forno.celo-testnet.org 
    -p d652abb81e8c686edba621a895531b1f291289b63b5ef09a94f686a5ecdd5db1 
    -c 6c3ee10ecef7eece161e225cd32ae18baa717176 
```
