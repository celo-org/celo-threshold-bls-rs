# Onchain DKG

1. Install the DKG CLI, hereafter called `dkg` which is used to perform the offline part of the computation
2. Install the Celo CLI, which will be used as a broadcast layer

We will use the Alfajores testnet for this example, which you can access by using `https://alfajores-forno.celo-testnet.org` as a `NODE_URL`. You can fund your account by inserting your `accountAddress` to the [Alfajores faucet](https://celo.org/developers/faucet).

The general pattern is: 
1. download data via `celocli`
2. perform transformation on the data via `dkg`
3. publish new data via `celocli`

## Joining Celo

You must have an account on the Celo network. You can do that by running:

`celocli account:new > .credentials`

This will give you a file with an `accountAddress` and a `privateKey` value, which you will use
to interact with the Celo blockchain. For the rest of the tutorial, we'll assume that the shell variables
`FROM` and `PRIVATE_KEY` are set with these values.

The `DKG_ADDRESS` variable will be given to you at the start of the DKG. 

If you want to deploy your own DKG contract you can run:

```
celocli dkg:deploy \
    --phaseDuration $DURATION_IN_BLOCKS \
    --threshold $THRESHOLD \
    --node $NODE_URL \
    --privateKey $PRIVATE_KEY
```

This command will output the deployed contract's address.

`DURATION_IN_BLOCKS` is the number of blocks each phase will be active for.
`THRESHOLD` is the DKG's threshold.

## 1. DKG Preparation

First, you must generate your DKG keypair:

```
dkg new --private-key dkg_privkey --public-key dkg_pubkey
```

Then, you must publish the public key to register yourself for the DKG.

```
celocli dkg:register \
  --address $DKG_ADDRESS \
  --node $NODE_URL \
  --privateKey $PRIVATE_KEY \
  --blsKey ./dkg_pubkey
```

Now you must wait until the DKG is started. You can do that by calling

```
celocli dkg:get \
  --method started \
  --address $DKG_ADDRESS \
  --node $NODE_URL
```

If the result is greater than 0, then that is the block in which the DKG was started.

### 2. Share Generation

Now that the DKG is started, you must get all DKG participants' BLS public keys. You do that
by calling:

```
celocli dkg:get \
  --method group \
  --address $DKG_ADDRESS \
  --node $NODE_URL > dkg_group
```

The data will be written to the `dkg_group` file. This file is used to run Phase 1 of the DKG. 

You must specify 2 output arguments for the `dkg publish-shares` command:
- `out-phase`: The path for your Phase 2 file which will be used in the next step. You MUST
not lose this file
- `output`: Where your shares will be written.

```
./dkg publish-shares --private-key dkg_privkey --group dkg_group --out-phase phase1 --output shares
```

You must then publish your shares to Celo, by calling:

```
celocli dkg:publish \
  --address $DKG_ADDRESS \
  --node $NODE_URL \
  --data ./shares
```

### 3. Response Generation

Once Phase 1 is over (after `DURATION_IN_BLOCKS` blocks), you must download
the published shares from the contract:

```
celocli dkg:get \
  --method shares \
  --address $DKG_ADDRESS \
  --node $NODE_URL > combined_shares
```

Then you must calculate your responses:

```
./dkg publish-responses --in-phase phase1 --out-phase phase2 --input ./combined_shares --output responses
```

Finally, you must publish your responses to Celo, by calling:

```
celocli dkg:publish \
  --address $DKG_ADDRESS \
  --node $NODE_URL \
  --data ./responses
```

### 4a. Try to get DKG Result 

As before, once Phase 2 is over (after `DURATION_IN_BLOCKS` blocks), you must download
the published responses from the contract:

```
celocli dkg:get \
  --method responses \
  --address $DKG_ADDRESS \
  --node $NODE_URL > combined_responses
```

Then you must try to calculate the final result:

```
./dkg try-finalize --in-phase phase2 --out-phase out_data --input ./combined_responses --output justifications
```

If the command does not prompt you to proceed to Phase 3, then `out_phase` will contain your share and the threshold public key.

### 4b. Going to Phase 3

If you received an error from the `try-finalize` command, then you must publish the justifications to the contract:

```
celocli dkg:publish \
  --address $DKG_ADDRESS \
  --node $NODE_URL \
  --data ./justifications
```

Once all justifications are published for each participant, you can download them by calling:

```
celocli dkg:get \
  --method justifications \
  --address $DKG_ADDRESS \
  --node $NODE_URL > combined_justifications
```

Then, you must call:

```
./dkg finalize --in-phase out_data --input combined_justifications --output result
```

This command will either produce your shares and the threshold public key at the file which corresponds to the `output` argument, or will
return an error (and the result will be empty).
