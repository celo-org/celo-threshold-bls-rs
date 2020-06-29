#!/bin/bash

NODE_URL="https://alfajores-forno.celo-testnet.org"

# We have 5 pre-funded Celo accounts on Alfajores via the faucet
# https://celo.org/developers/faucet
ACC1='{"address":"0xb41998dc0db80898e691127ed06444ae90a0724b","privateKey":"0b9c5fa5b83e7b7625c7fee0f576cd2118786733e13c2a83bfe771d9d4fd0fb3"}'
ACC2='{"address":"0x48ad174c5b3863d9c129e8e700cd452a14b3c627","privateKey":"334dfa0dc5abeb2288f83374fb7b87c4dcc68ad4f3caffc961685f4011b9cb76"}'
ACC3='{"address":"0x5b8e00d725225bcd138062b187239893a8e99c27","privateKey":"7e7b2279508e0f7ad3b028773fa53bf11933ed716e6c55b95ef2073afcce4f4c"}'
ACC4='{"address":"0xc46ba6ba7604cccd16196878d98adbb610d7346a","privateKey":"ef0c8c2e816633fd336defe3f824bec141b2d2d01267d38344d55bb2fce05da6"}'
ACC5='{"address":"0x111e8d6dffa22859efa38af6b1d7f0fb21840576","privateKey":"c5183dde6c2431505e2a567bb9f69d7aa90e45295be9324abee773f85d6101cf"}'

# Results of a previous DKG round with 4 participants. The re-sharing will convert
# the previous 3-of-4 deal to a 4-of-5 one.
OLD_CONTRACT="de8542be84aa7f6c382c1b1bfa93283f24fa7ca6"
PUBLIC_POLYNOMIAL="0300000000000000dd51cfd48123c2836a0de36270b2f10e55001bad137aee176b689e17d28b91e27af59f989a943afc9bb511bae6391800585688c0a2465af3966de1b8ec451aa0194ab4436692cbbd1e868182faea2eff72cebba992738690e77d24b0ae59dd00a7a745589d68fceadda727613d23ed18b6b5322cf7f6ea0785c139cfba86f06300a5be7def4367376edddb4f82dc7300bb1a97786e84c508c468f1d59aeec2b71a90928feb8c3da40a2301fc8a921c03594d360a4b74e781ca7ac2a36711180178dca759206c79485e2c7b6b5edf279715eea0b71075c9c05aeff23fd67af7611cc577fa2b00a135d576229f13c07101b678cf6ad8e1f82b4520f3167964d9ff69f3dc49adce1837dfb2b84f65cfceb689ffa39c29a1b6aa8b7abac89a0f8f80"
ACC1_SHARE="00000000a46799e27bb268a79b430977b5de7dd7b8c6b16a33dbc9556c3e1a56e37cb504"
ACC2_SHARE="01000000527cc20fcbf95caf0aa514d624438fe2f6206f11ad4d753c058cec273572f20d"
ACC3_SHARE="03000000d14911c90127d94914b34b139655e0ae372dfbc363329aaa92633d8fa0890e10"
ACC4_SHARE="020000000b1d955ca220ccdedc74d5d4c5703e997578629c5337edc22d2a852935884805"

# This example uses a threshold of 4 with each phase lasting 7 blocks (~45 sec)
THRESHOLD=4
PHASE_DURATION=7

private_key() {
    echo $1 | jq -r '.privateKey'
}

address() {
    RES=$(echo $1 | jq -r '.address')
    echo ${RES#"0x"}
}

# First we deploy the resharing contract and get its address
ADDR=$(cargo run --bin dkg-cli deploy \
    -n $NODE_URL \
    -p $(private_key $ACC1) \
    --threshold $THRESHOLD \
    --phase-duration $PHASE_DURATION)
# strip the unused info
ADDR=${ADDR#"Contract deployed at: 0x"}

# The admin allows all addresses (new ones too)
cargo run --bin dkg-cli -- allow \
    -n $NODE_URL \
    -p $(private_key $ACC1) \
    -c $ADDR \
    -a $(address $ACC1) \
    -a $(address $ACC2) \
    -a $(address $ACC3) \
    -a $(address $ACC4) \
    -a $(address $ACC5)
 
# Resharing commands are almost the same as the normal DKG commands, but you also
# have to provide some additional info from the previous DKG, the contract's address
# and the public polynomial which was computed
# - if you were a previous participant you also need to supply your share
reshare() {
    yes | cargo run --bin dkg-cli -- reshare \
        -n $NODE_URL \
        -p $(private_key $1) \
        -c $ADDR \
        -o $3 \
        --share $2 \
        --public-polynomial $PUBLIC_POLYNOMIAL \
        --previous-contract-address $OLD_CONTRACT
}

new_member() {
    yes | cargo run --bin dkg-cli -- reshare \
        -n $NODE_URL \
        -p $(private_key $1) \
        -c $ADDR \
        -o $2 \
        --public-polynomial $PUBLIC_POLYNOMIAL \
        --previous-contract-address $OLD_CONTRACT
}

# Each participant launches the job
reshare $ACC1 $ACC1_SHARE ./new_acc1_share &
reshare $ACC2 $ACC2_SHARE ./new_acc2_share &
reshare $ACC3 $ACC3_SHARE ./new_acc3_share &
reshare $ACC4 $ACC4_SHARE ./new_acc4_share &

# the 5th participant is new
new_member $ACC5 ./new_acc5_share &
  
# # sleep 10 seconds so that all participants register
sleep 10

# go!
cargo run --bin dkg-cli -- start \
    -n $NODE_URL \
    -p $(private_key $ACC1) \
    -c $ADDR
