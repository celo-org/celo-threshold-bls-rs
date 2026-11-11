// Checks that a Swift caller can import the xcframework's module and link the
// library. `just check-ios-xcframework` builds this for the device and for
// both simulator architectures; nothing runs it, because that would need a
// device or a booted simulator. The C ABI's behaviour is covered by
// smoke_test.c.

import BlindThresholdBls

let seed = [UInt8](repeating: 0x61, count: Int(SEED_LEN))
var keypair: OpaquePointer?
let generated = seed.withUnsafeBufferPointer { bytes -> Bool in
    var buffer = Buffer(ptr: bytes.baseAddress, len: bytes.count)
    return keygen(&buffer, &keypair)
}
precondition(generated, "keygen refused a full-length seed")
destroy_keypair(keypair)
