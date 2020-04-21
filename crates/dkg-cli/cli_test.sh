#!/bin/bash

cargo build
rm -f node* dkg_group pkey0 pkey1 pkey2 phase* combined* responses* shares* justifications* tkey*

### 1. Preparation

DKG=../../target/debug/dkg
COO=../../target/debug/coordinator

# Each DKG participant generates their keypair

$DKG new --index 0 --private-key pkey0 --public-key node0
$DKG new --index 1 --private-key pkey1 --public-key node1
$DKG new --index 2 --private-key pkey2 --public-key node2


# The coordinator gets their public keys and creates the group with a 2-of-n threshold (n = 3 in this case since it is equal to the number of node\* files)

$COO setup --threshold 2 --nodes "node*" --group ./dkg_group

echo "Setup complete"

### 2. Share Generation

# Each DKG participant downloads the `dkg_group` file and uses it to run Phase 1. They also specify
# where the path for their Phase 2 file which they'll use in the next step. 

# The `shares` represents the data which will then be uploaded to the coordinator (the coordinator acts as the board).

$DKG publish-shares --private-key pkey0 --group dkg_group --out-phase phase1_node0 --output shares0
# $DKG publish-shares --private-key pkey1 --group dkg_group --out-phase phase1_node1 --output shares1
$DKG publish-shares --private-key pkey2 --group dkg_group --out-phase phase1_node2 --output shares2

# The coordinator gathers the shares from Phase 1 and combines them

$COO combine-shares --input "./shares*" --output ./combined_shares

echo "Shares published"

### 3. Response Generation

# Participants download the Phase 1 shares from the coordinator, and generate their responses.
# 
$DKG publish-responses --in-phase phase1_node0 --out-phase phase2_node0 --input ./combined_shares --output responses0
# $DKG publish-responses --in-phase phase1_node1 --out-phase phase2_node1 --input ./combined_shares --output responses1
$DKG publish-responses --in-phase phase1_node2 --out-phase phase2_node2 --input ./combined_shares --output responses2

# The coordinator gathers the responses from Phase 2 and combines them

$COO combine-responses --input "./responses*" --output ./combined_responses

echo "Responses published"

### 4a. Try to get DKG Result 

$DKG try-finalize --in-phase phase2_node0 --out-phase tkey0 --input ./combined_responses --output justifications0
# $DKG try-finalize --in-phase phase2_node1 --out-phase tkey1 --input ./combined_responses --output justifications1
$DKG try-finalize --in-phase phase2_node2 --out-phase tkey2 --input ./combined_responses --output justifications2

echo "Phase 3"

# If the command does not prompt you to proceed to Phase 3, then `out-phase` will contain your share and the threshold public key.
# Otherwise, it will contain the information for Phase 3. the `output` must also be sent to the coordinator, who will then execute:

$COO combine-justifications --input "./justifications*" --output ./combined_justifications

### 4b. Justifications (if needed)

$DKG finalize --in-phase tkey0 --input combined_justifications --output result0
# $DKG finalize --in-phase tkey0 --input combined_justifications --output result1
$DKG finalize --in-phase tkey2 --input combined_justifications --output result2
