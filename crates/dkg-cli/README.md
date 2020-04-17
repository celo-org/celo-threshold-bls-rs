# Distributed Key Generation CLI

This crate provides a CLI to the provided DKG. 

As explained in [`dkg-core`](../dkg-core), there are a few phases. For each phase, users perform some computation which is then published to a "board". An authenticated channel is assumed for publishing to the board. In this CLI, the board is assumed to be a coordinator who authenticates a user's participation before adding it to their state. Before advancing to each of the next phases, the board gathers all participants' contributions and combines them in a file. These contributions are then used by each participant in the next round.

## Examples

TODO
