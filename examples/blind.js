// Choose target depending on https://rustwasm.github.io/docs/wasm-pack/commands/build.html#target
// We use --target nodejs here
const threshold = require("../pkg/threshold")

const msg = Buffer.from("hello world")
const user_seed = Buffer.from("the user seed which must be at least 32 bytes or else it will return _unreachable_")

const blinded_msg = threshold.blind(msg, user_seed)
const blind_msg = blinded_msg.message

// generate the service key
const service_seed = Buffer.from("servie seed (must be at least 32 bytes or else it will return _unreachable_)")
const keypair = threshold.keygen(service_seed)
// bind it locally because otherwise it will clone each time you call the struct
const private_key = keypair.private
const public_key = keypair.public

// signature gets signed by service
const blind_sig = threshold.sign(private_key, blind_msg)

// user unblinds the signature
const unblinded_sig = threshold.unblind_signature(blind_sig, blinded_msg.scalar)

// user verifies the msg by the pubkey of the service
const verified = threshold.verify_sign(public_key, msg, unblinded_sig)

// should be true
if (verified === true) {
    console.log("Verification successful")
} else {
    console.log("Verification failed")
}
