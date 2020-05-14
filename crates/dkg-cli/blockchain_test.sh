#!/bin/bash

# In order to run this example, your environment must have the following variables set:
# 1. DKG_ADDRESS:  Address of the DKG contract
# 2. NODE_URL: Your Celo node
# 3. DKG: Path to the DKG binary
# 4. CELO: Path to celocli's binary (celo-monorepo/packages/cli/bin/run)
# We assume that the contract has already been deployed and you have received its address
# via: $CELO dkg:deploy --node $NODE_URL --privateKey $PRIVATE_KEY --from $FROM --phaseDuration 12 --threshold 2

### 1. Preparation

# celo keys (celocli account:new)
PRIVKEY0=d6e415ef1f2c7e794d187768870aca9026205578803178b698a7e6bceaa4cc09
ADDR0=0xC6985A3B2Ba4beA0aA8aa83acE8F5051405E9FCD
PRIVKEY1=f40836c27baa5b732a4d8d961ec4621b91118d9aca5b151647b179189dacc7ce
ADDR1=0x565aE96B1A4aa7147D9701EC78A7b25E3D2a9C68
PRIVKEY2=517b5d239aadb2cba21d345bcfe7ffcf4062065d4e86680d4ffc0a7921f58205
ADDR2=0xF27515F124703F7c5eF0095b011c1f1D64955aA5

# Each DKG participant generates their keypair and publishes it

$DKG new --private-key privkey0 --public-key pubkey0
$CELO dkg:register --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY0 --from $ADDR0 --blsKey pubkey0 &

$DKG new --private-key privkey1 --public-key pubkey1
$CELO dkg:register --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY1 --from $ADDR1 --blsKey pubkey1 &

$DKG new --private-key privkey2 --public-key pubkey2
$CELO dkg:register --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY2 --from $ADDR2 --blsKey pubkey2 &

echo "Setup complete"
read -p "Press enter to start the DKG"
$CELO dkg:start --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY0 --from $ADDR0
 
### 2. Share Generation (3 parties registed but only 2 appeared!)

$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method group > dkg_group

$DKG publish-shares --private-key privkey0 --group ./dkg_group --out-phase phase1_node0 --output shares0
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY0 --from $ADDR0 --data ./shares0 &

$DKG publish-shares --private-key privkey1 --group dkg_group --out-phase phase1_node1 --output shares1
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY1 --from $ADDR1 --data ./shares1 &

echo "Shares published"
read -p "Press enter to continue after Phase 1 has ended"
$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method shares > combined_shares

# 3. Response Generation

$DKG publish-responses --in-phase phase1_node0 --out-phase phase2_node0 --input ./combined_shares --output responses0
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY0 --from $ADDR0 --data ./responses0 &

$DKG publish-responses --in-phase phase1_node1 --out-phase phase2_node1 --input ./combined_shares --output responses1
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY1 --from $ADDR1 --data ./responses1 &

echo "Responses published"
read -p "Press enter to continue after Phase 2 has ended"
$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method responses > combined_responses

### 4. Since the 3rd participant didn't publish, we have to go to phase 3

$DKG try-finalize --in-phase phase2_node0 --out-phase phase3_node0 --input ./combined_responses --output justifications0
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY0 --from $ADDR0 --data ./justifications0 &

$DKG try-finalize --in-phase phase2_node1 --out-phase phase3_node1 --input ./combined_responses --output justifications1
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVKEY1 --from $ADDR1 --data ./justifications1 &

### 5. Justifications

echo "Justifications Published"
read -p "Press enter to continue after Phase 3 has ended"
$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method justifications > combined_justifications

$DKG finalize --in-phase phase3_node0 --input combined_justifications --output result0
$DKG finalize --in-phase phase3_node1 --input combined_justifications --output result1
