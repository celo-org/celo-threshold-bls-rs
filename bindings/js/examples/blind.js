// Simple Example of blinding, signing, unblinding and verifying.

// Import the library
const threshold = require("../src/blind_threshold_bls")
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
const blind_sig = threshold.signBlindedMessage(private_key, blind_msg)

// User unblinds the signature with this scalar
const unblinded_sig = threshold.unblind(blind_sig, blinded_msg.blindingFactor)

// User verifies the unblinded signature on his unblinded message
// (this throws on error)
threshold.verify(public_key, msg, unblinded_sig)
console.log("Verification successful")
