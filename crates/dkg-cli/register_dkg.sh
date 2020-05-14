#!/bin/bash -e

# In order to run this example, your environment must have the following variables set:
# 1. DKG_ADDRESS:  Address of the DKG contract
# 2. NODE_URL: Your Celo node
# 3. DKG: Path to the DKG binary
# 4. CELO: Path to celocli's binary (celo-monorepo/packages/cli/bin/run)
# 5. PRIVATE_KEY: Private key of the user
# 6. FROM: Address of the user
# We assume that the contract has already been deployed and you have received its address
# via: $CELO dkg:deploy --node $NODE_URL --privateKey $PRIVATE_KEY --from $FROM --phaseDuration 12 --threshold 2

### 1. Preparation

# Each DKG participant generates their keypair and publishes it

$DKG new --private-key privkey --public-key pubkey
$CELO dkg:register --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --blsKey pubkey

echo "Registration complete"
