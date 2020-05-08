# JF-DKG with a blockchain as a broadcast layer

## Build & Test

Internally, uses [`buidler`](https://buidler.dev/) to build and test the code.

```
yarn
yarn build
yarn test
```

Methods are provided for each DKG participant to call in each phase:
- `register`
- `publishShares`
- `publishResponses`
- `publishJustifications`

## Privileged Account

The contract's deployer is the on who is able to start the DKG procedure by calling `start` after
enough participants have registered.

## Phase 0

Participants register during that time period by calling the `register(bytes blsPublicKey)` function.
Participants that have not registered in this phase will not be able to participate in any of the 
following stages.

## Phase 1

Phase 1 is initiated once the `start` function is called by the DKG contract's deployer. Each of the
registered participants MAY publish their shares ONCE.

## Phase 2

The DKG transition automatically to Phase 2 after `N` blocks have passed since the start of Phase 1. Each
of the registered participants MAY publish their responses ONCE.

## Phase 3

The DKG transition automatically to Phase 3 after `N` blocks have passed since the start of Phase 2 (so in total `2 * N` blocks
since the `start` function was called). Each of the registered participants MAY publish their justifications ONCE.

_note: This phase should not be required by users published all their shares in Phase 1._
