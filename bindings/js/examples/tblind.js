// Example of how threshold signing is expected to be consumed from the JS side

// Import the library
const threshold = require("../src/blind_threshold_bls")
const crypto = require('crypto')

// Get a message and a secret for the user
const msg = Buffer.from("hello world")
const userSeed = crypto.randomBytes(32)

// Blind the message
const blinded = threshold.blind(msg, userSeed)
const blindedMessage = blinded.message

// Generate the secret shares for a 3-of-4 threshold scheme
const t = 3;
const n = 4;
const keys = threshold.thresholdKeygen(n, t, crypto.randomBytes(32))
const shares = keys.shares
const polynomial = keys.polynomial

// each of these shares proceed to sign teh blinded sig
let sigs = []
for (let i = 0 ; i < keys.numShares(); i++ ) {
    const sig = threshold.partialSignBlindedMessage(keys.getShare(i), blindedMessage)
    sigs.push(sig)
}

// The combiner will verify all the individual partial signatures
for (const sig of sigs) {
    threshold.partialVerifyBlindSignature(polynomial, blindedMessage, sig)
}

const blindSig = threshold.combine(t, flattenSigsArray(sigs))

// User unblinds the combined threshold signature with his scalar
const sig = threshold.unblind(blindSig, blinded.blindingFactor)

// User verifies the unblinded signautre on his unblinded message
threshold.verify(keys.thresholdPublicKey, msg, sig)
console.log("Verification successful")

function flattenSigsArray(sigs) {
    return Uint8Array.from(sigs.reduce(function(a, b){
      return Array.from(a).concat(Array.from(b));
    }, []));
}
