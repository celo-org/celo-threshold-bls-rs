# Blind Threshold BLS Signatures


This library provides wasm bindings for producing and verifying blind threshold signatures
on BLS12-377. This is done by utilizing [`wasm-pack`](https://github.com/rustwasm/wasm-pack) and
the underlying [Rust library](https://github.com/celo-org/celo-threshold-bls-rs).

You can find details on the functionalities provided per function by inspecting
the [Typescript types file](./src/blind_threshold_bls.d.ts)

Install by running: `npm install @celo/blind-threshold-bls`

## Building from source

The package contents under `src/` are generated from the Rust crate in this
repository and are not checked in. To build them:

```
cd crates/threshold-bls-ffi
wasm-pack build --target nodejs -- --features=wasm
cp pkg/blind* ../../bindings/js/src/
```

Then run the test suite from this directory with `npm ci && npm test`.

## Examples

Currently there are 2 examples available. You can run them and inspect the comments in the files
by executing:

```
$ node examples/blind.js
$ node examples/tblind.js
```

## Usage

### Simple signing

```javascript
// Simple Example of blinding, signing, unblinding and verifying.

// Import the library
const threshold = require("@celo/blind-threshold-bls")
const crypto = require('crypto')

// Get a message and a secret for the user
const msg = Buffer.from("hello world")
const user_seed = crypto.randomBytes(32)

// Blind the message
const blinded_msg = threshold.blind(msg, user_seed)
const blind_msg = blinded_msg.message

// Generate a keypair for the service
const service_seed = crypto.randomBytes(32)
const keypair = threshold.keygen(service_seed)
const private_key = keypair.privateKey
const public_key = keypair.publicKey

// Sign the user's blinded message with the service's private key
const blind_sig = threshold.sign(private_key, blind_msg)

// User unblinds the signature with this scalar
const unblinded_sig = threshold.unblind(blind_sig, blinded_msg.blindingFactor)

// User verifies the unblinded signature on his unblinded message
// (this throws on error)
threshold.verify(public_key, msg, unblinded_sig)
console.log("Verification successful")
```

### Threshold Signatures


```javascript
// Example of how threshold signing is expected to be consumed from the JS side

// Import the library
const threshold = require("@celo/blind-threshold-bls")
const crypto = require('crypto')
// Helper
function flattenSigsArray(sigs) {
    return Uint8Array.from(sigs.reduce(function(a, b){
      return Array.from(a).concat(Array.from(b));
    }, []));
}

// Get a message and a secret for the user
const msg = Buffer.from("hello world")
const userSeed = crypto.randomBytes(32)

// Blind the message
const blinded = threshold.blind(msg, userSeed)
const blindedMessage = blinded.message

// Generate the secret shares for a 3-of-4 threshold scheme
//
// WARNING: thresholdKeygen is a helper for local testing. Do not use it in
// production, unless you trust the party that generated the keys.
const t = 3;
const n = 4;
const keys = threshold.thresholdKeygen(n, t, crypto.randomBytes(32))
const shares = keys.shares
const polynomial = keys.polynomial

// each of these shares proceed to sign the blinded sig
let sigs = []
for (let i = 0 ; i < keys.numShares(); i++ ) {
    const sig = threshold.partialSign(keys.getShare(i), blindedMessage)
    sigs.push(sig)
}

// The combiner will verify all the individual partial signatures
for (const sig of sigs) {
    threshold.partialVerify(polynomial, blindedMessage, sig)
}

const blindSig = threshold.combine(t, flattenSigsArray(sigs))

// User unblinds the combined threshold signature with his scalar
const sig = threshold.unblind(blindSig, blinded.blindingFactor)

// User verifies the unblinded signature on his unblinded message
threshold.verify(keys.thresholdPublicKey, msg, sig)
console.log("Verification successful")
```
