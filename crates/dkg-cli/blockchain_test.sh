#!/bin/bash

NODE_URL="https://alfajores-forno.celo-testnet.org"

# We have 4 pre-funded Celo accounts on Alfajores via the faucet
# https://celo.org/developers/faucet
ACC1='{"address":"0xb41998dc0db80898e691127ed06444ae90a0724b","privateKey":"0b9c5fa5b83e7b7625c7fee0f576cd2118786733e13c2a83bfe771d9d4fd0fb3"}'
ACC2='{"address":"0x48ad174c5b3863d9c129e8e700cd452a14b3c627","privateKey":"334dfa0dc5abeb2288f83374fb7b87c4dcc68ad4f3caffc961685f4011b9cb76"}'
ACC3='{"address":"0x5b8e00d725225bcd138062b187239893a8e99c27","privateKey":"7e7b2279508e0f7ad3b028773fa53bf11933ed716e6c55b95ef2073afcce4f4c"}'
ACC4='{"address":"0xc46ba6ba7604cccd16196878d98adbb610d7346a","privateKey":"ef0c8c2e816633fd336defe3f824bec141b2d2d01267d38344d55bb2fce05da6"}'

# This example uses a threshold of 3 with each phase lasting 7 blocks (~45 sec)
THRESHOLD=3
PHASE_DURATION=7

# Helper to get the private key from the account json
private_key() {
    echo $1 | jq -r '.privateKey'
}

# Helper to get the address key from the account json
address() {
    ADDR=$(echo $1 | jq -r '.address')
    # strip the 0x prefix
    echo ${ADDR#"0x"}
}

# First we deploy the contract and get its address
ADDR=$(cargo run --bin dkg-cli deploy \
    -n $NODE_URL \
    -p $(private_key $ACC1) \
    --threshold $THRESHOLD \
    --phase-duration $PHASE_DURATION)
# strip the unused info
ADDR=${ADDR#"Contract deployed at: 0x"}

# The admin whitelists all addresses
cargo run --bin dkg-cli -- whitelist \
    -n $NODE_URL \
    -p $(private_key $ACC1) \
    -c $ADDR \
    -a $(address $ACC1) \
    -a $(address $ACC2) \
    -a $(address $ACC3) \
    -a $(address $ACC4)
 
# helper to run the DKG command
run() {
    yes | cargo run --bin dkg-cli -- run -n $NODE_URL -p $(private_key $1) -c $ADDR -o $2
}

# Each participant launches the job
run $ACC1 ./acc1_share &
run $ACC2 ./acc2_share &
run $ACC3 ./acc3_share &
run $ACC4 ./acc4_share &
 
# sleep 10 seconds so that all participants register
sleep 10

# go!
cargo run --bin dkg-cli -- start \
    -n $NODE_URL \
    -p $(private_key $ACC1) \
    -c $ADDR
