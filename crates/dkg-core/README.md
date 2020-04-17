# DKG Core

The DKG is based on the [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems
](https://link.springer.com/article/10.1007/s00145-006-0347-3) paper.

The implementation is a state machine which has Phases 0 to 3. Phase 3 is only reachable if any of the
n parties does not publish its shares in the first phase. If less than t parties participate in any stage,
the DKG fails.

TODO: Add more details on how the DKG works.
