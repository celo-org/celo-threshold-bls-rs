# Distributed Key Generation CLI

This crate provides a CLI to the provided DKG. 

As explained in [`dkg-core`](../dkg-core), there are a few phases. For each phase, users perform some computation which is then published to a "board". An authenticated channel is assumed for publishing to the board. In this CLI, the board is assumed to be a coordinator who authenticates a user's participation before adding it to their state. Before advancing to each of the next phases, the board gathers all participants' contributions and combines them in a file. These contributions are then used by each participant in the next round.

## Examples

The `output` from each command should be uploaded to the coordinator. The `out-phase` should be saved and used as the `in-phase` after the coordinator has published the next phase's data.

### 1. Preparation

Each DKG participant generates their keypair

```
./dkg new --index 0 --private-key pkey0 --public-key node0
./dkg new --index 1 --private-key pkey1 --public-key node1
./dkg new --index 2 --private-key pkey2 --public-key node2
```

The coordinator gets their public keys and creates the group with a 2-of-n threshold (n = 3 in this case since it is equal to the number of node\* files)

```
./coordinator setup --threshold 2 --nodes node* --group ./dkg_group
```

### 2. Share Generation

Each DKG participant downloads the `dkg_group` file and uses it to run Phase 1. They also specify
where the path for their Phase 2 file which they'll use in the next step. 

The `shares` represents the data which will then be uploaded to the coordinator (the coordinator acts as the board).

```
./dkg publish-shares --private-key pkey0 --group dkg_group --out-phase phase1_node0 --output shares0
./dkg publish-shares --private-key pkey1 --group dkg_group --out-phase phase1_node1 --output shares1
./dkg publish-shares --private-key pkey2 --group dkg_group --out-phase phase1_node2 --output shares2
```

The coordinator gathers the shares from Phase 1 and combines them

```
./coordinator combine-shares --input "./shares*" --output ./combined_shares
```

### 3. Response Generation

Participants download the Phase 1 shares from the coordinator, and generate their responses.

```
./dkg publish-responses --in-phase phase1_node0 --out-phase phase2_node0 --input ./combined_shares --output responses0
./dkg publish-responses --in-phase phase1_node1 --out-phase phase2_node1 --input ./combined_shares --output responses1
./dkg publish-responses --in-phase phase1_node2 --out-phase phase2_node2 --input ./combined_shares --output responses2
```

The coordinator gathers the responses from Phase 2 and combines them

```
./coordinator combine-responses --input "./responses*" --output ./combined_responses
```

### 4a. Try to get DKG Result 

```
./dkg try-finalize --in-phase phase2_node0 --out-phase out_node0 --input ./combined_responses --output justifications0
./dkg try-finalize --in-phase phase2_node1 --out-phase out_node1 --input ./combined_responses --output justifications1
./dkg try-finalize --in-phase phase2_node2 --out-phase out_node2 --input ./combined_responses --output justifications2
```

If the command does not prompt you to proceed to Phase 3, then `out-phase` will contain your share and the threshold public key.
Otherwise, it will contain the information for Phase 3. the `output` must also be sent to the coordinator, who will then execute:

```
./coordinator combine-justifications --input "./justifications*" --output ./combined_justifications
```

### 4b. Justifications 

```
./dkg finalize --in-phase node0 --input combined_justifications --output result0
./dkg finalize --in-phase node1 --input combined_justifications --output result1
./dkg finalize --in-phase node2 --input combined_justifications --output result2
```

This command will either produce your shares and the threshold public key at the file which corresponds to the `output` argument, or will
return an error (and the result will be empty).
