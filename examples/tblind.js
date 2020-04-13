// Example of how threshold signing is expected to be consumed from the JS side

// Import the library
const threshold = require("../pkg/threshold")
const crypto = require('crypto')

// Get a message and a secret for the user
const msg = Buffer.from("hello world")
const user_seed = crypto.randomBytes(32)

// Blind the message
const blinded_msg = threshold.blind(msg, user_seed)
const blind_msg = blinded_msg.message

// Generate the secret shares for a 3-of-4 threshold scheme
const t = 3;
const n = 4;
const keys = threshold.threshold_keygen(n, t, crypto.randomBytes(32))
const shares = keys.shares
const polynomial = keys.polynomial

// each of these shares proceed to sign teh blinded sig
let sigs = []
for (let i = 0 ; i < keys.num_shares(); i++ ) {
    const sig = threshold.partial_sign(keys.get_share(i), blind_msg)
    sigs.push(sig)
}

// The combiner will verify all the individual partial signatures... 
// let count = 0;
// for (const sig of sigs) {
//     if (threshold.verify_partial_blind_signature(polynomial, blind_msg, sig)) {
//         count++
//     }
//     console.log("verified", count)
// 
//     // t-of-n is enough!
//     if (count == t) {
//         break
//     }
// }
// 
// // ...and if they were at least `t`, he will combine them
// if count < t {
//     console.log("INVALID THRESHOLD")
//     return
// }

const blind_sig = threshold.combine(t, flattenSigsArray(sigs))

// User unblinds the combined threshold signature with his scalar
const unblinded_sig = threshold.unblind_signature(blind_sig, blinded_msg.scalar)

// User verifies the unblinded signautre on his unblinded message
const verified = threshold.verify_sign(keys.threshold_public_key, msg, unblinded_sig)
if (verified === true) {
    console.log("Verification successful")
} else {
    console.log("Verification failed")
}

function flattenSigsArray(sigs) {
    return Uint8Array.from(sigs.reduce(function(a, b){
      return Array.from(a).concat(Array.from(b));
    }, []));
}
