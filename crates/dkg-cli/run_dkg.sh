#!/bin/bash -e

if [[ $1 == "create-account" ]]; then
  $CELO account:new 2>&1 | grep -v libusb
  exit 0
fi

if [[ $1 == "clean" ]]; then
  rm dkg_phase
  exit 0
fi

if [[ ! -f dkg_phase ]]; then
  echo -1 > dkg_phase
fi

DKG_CONFIG=dkg_config
if [[ $1 != "" ]]; then
  DKG_CONFIG=$1
fi

touch ${DKG_CONFIG}
source ${DKG_CONFIG}

function exit_if_empty() {
  if [[ $1 == "" ]]; then
    echo "$2 is not set, exiting"
    exit 1
  fi
}

exit_if_empty "$FROM" "FROM"
exit_if_empty "$PRIVATE_KEY" "PRIVATE_KEY"
exit_if_empty "$DKG_ADDRESS" "DKG_ADDRESS"
exit_if_empty "$NODE_URL" "NODE_URL"

function exit_if_command_failed() {
  if [[ ${PIPESTATUS[0]} != 0 ]]; then
    echo "Error, exiting"
    exit 1
  fi
}

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
  echo `$CELO dkg:get --method phase --node $NODE_URL --address $DKG_ADDRESS 2>&1  | grep -v libusb | awk '{print $3}'`
}

function do_phase0 () {
  $DKG new --private-key privkey --public-key pubkey
  $CELO dkg:register --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --blsKey pubkey 2>&1 | grep -v libusb
  exit_if_command_failed
  echo "Registration complete"
  echo 0 > dkg_phase
}

function do_phase1 () {
  ### 2. Share Generation (3 parties registed but only 2 appeared!)

  $CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method group 2>&1 | grep -v libusb > dkg_group
  $CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method participants 2>&1 | grep -v libusb > dkg_group_addresses
  exit_if_command_failed

  cr=`echo $'\n.'`
  cr=${cr%.}

  while true; do
    read -p "${cr}${cr}${cr}********************************${cr}DKG group details: $(echo "" && cat dkg_group_addresses && echo "DKG group hash: `sha256sum dkg_group_addresses | awk '{print $1}'`") `echo $'\n\nDo you approve the DKG group details? > '`" yn
      case $yn in
          [Yy]* ) break;;
          [Nn]* ) exit 1;;
          * ) echo "Please answer yes or no.";;
      esac
  done


  $DKG publish-shares --private-key privkey --group ./dkg_group --out-phase phase1_node --output shares
  exit_if_command_failed
  $CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --data ./shares 2>&1 | grep -v libusb
  exit_if_command_failed
  echo "Shares published"

  echo 1 > dkg_phase
  #do_phase1
}

function do_phase2 () {
  ### 3. Response Generation
  $CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method shares 2>&1 | grep -v libusb > combined_shares
  exit_if_command_failed

  $DKG publish-responses --in-phase phase1_node --out-phase phase2_node --input ./combined_shares --output responses
  exit_if_command_failed
  $CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --data ./responses 2>&1 | grep -v libusb
  exit_if_command_failed
  echo "Responses published"

  echo 2 > dkg_phase
  #do_phase2
}

function do_phase3 () {
  $CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method responses 2>&1 | grep -v libusb > combined_responses
  exit_if_command_failed

  ### 4. Since the 3rd participant didn't publish, we have to go to phase 3

  PHASE3_OUTPUT=`$DKG try-finalize --in-phase phase2_node --out-phase phase3_node --input ./combined_responses --output justifications`
  if  [[ "$PHASE3_OUTPUT" == "Success"* ]]
  then
    echo $PHASE3_OUTPUT
    exit 0
  fi

  $CELO dkg:publish --node $NODE_URL --address $DKG_ADDRESS --privateKey $PRIVATE_KEY --from $FROM --data ./justifications 2>&1 | grep -v libusb
  exit_if_command_failed
  echo "Justifications Published"
  echo 3 > dkg_phase
  #do_phase3
}

function do_phase4 () {
  ### 5. Justifications

  $CELO dkg:get --node $NODE_URL --address $DKG_ADDRESS --method justifications 2>&1 | grep -v libusb > combined_justifications
  exit_if_command_failed

  $DKG finalize --in-phase phase3_node --input combined_justifications --output result
  exit_if_command_failed
  echo 4 > dkg_phase
}

function do_phase5() {
  echo "DKG done!"
  exit 0
}

echo "Participating in DKG at address $DKG_ADDRESS"

while true; do
  phase="$(get_phase)"
  done_phase=$(<dkg_phase)
  if  [[ "$done_phase" == "$phase" ]]; then
    echo "Phase is still $phase. Sleeping for $SLEEP_TIME seconds."
    sleep $SLEEP_TIME
    continue
  fi
  if  [[ "0" == "$phase" ]]; then
    do_phase0
    continue
  fi
  do_phase$((done_phase + 1))
done
