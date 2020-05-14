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

SLEEP_TIME=5

function get_phase () {
  echo `$CELO dkg:get --method phase --node $NODE_URL --address $DKG_ADDRESS | awk '{print $3}'`
}

function wait_for_phase () {
  local phase="$(get_phase)"
  while [ "$phase" == "$1" ]
  do
    echo "Phase is still $phase. Sleeping for $SLEEP_TIME seconds."
    sleep $SLEEP_TIME
    phase="$(get_phase)"
  done
}

### 1. Preparation

wait_for_phase 0
### 2. Share Generation (3 parties registed but only 2 appeared!)

$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method group > dkg_group

$DKG publish-shares --private-key privkey --group ./dkg_group --out-phase phase1_node --output shares
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --data ./shares

echo "Shares published"
wait_for_phase 1
$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method shares > combined_shares

# 3. Response Generation

$DKG publish-responses --in-phase phase1_node --out-phase phase2_node --input ./combined_shares --output responses
$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --data ./responses

echo "Responses published"
wait_for_phase 2
$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method responses > combined_responses

### 4. Since the 3rd participant didn't publish, we have to go to phase 3

PHASE3_OUTPUT=`$DKG try-finalize --in-phase phase2_node --out-phase phase3_node --input ./combined_responses --output justifications`
if  [[ "$PHASE3_OUTPUT" == "Success"* ]]
then
  echo $PHASE3_OUTPUT
  exit 0
fi

$CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --data ./justifications

### 5. Justifications

echo "Justifications Published"
wait_for_phase 3
$CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method justifications > combined_justifications

$DKG finalize --in-phase phase3_node --input combined_justifications --output result
