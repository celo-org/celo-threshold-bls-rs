// add this so that we can be more explicit about unsafe calls inside unsafe functions
#![allow(unused_unsafe)]

// This crate is nothing but its binding surfaces. With none of them enabled it
// still builds, and produces a library exporting no symbols — which is what
// shipped as an empty Android `.so` until 0025630 gave the cross builds a
// default feature. Refuse to compile instead of handing anyone that artifact.
#[cfg(not(any(feature = "ffi", feature = "wasm", feature = "jvm")))]
compile_error!(
    "threshold-bls-ffi builds a binding surface and has none enabled; pass --features with one of \
     ffi (the C ABI), wasm or jvm"
);

// The three binding surfaces are independent: enabling several features
// compiles all of them, so `--all-features` builds, tests and lints the lot.
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "jvm")]
pub mod jni_bridge;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "ffi")]
pub(crate) type Signature = <SigScheme as Scheme>::Signature;
#[cfg(feature = "ffi")]
pub const PUBKEY_LEN: usize = 96;
#[cfg(feature = "ffi")]
pub const PRIVKEY_LEN: usize = 32;

use threshold_bls::{poly::Idx, schemes::bls12_377::G2Scheme as SigScheme, sig::Scheme};

#[allow(dead_code)]
pub(crate) type PublicKey = <SigScheme as Scheme>::Public;
#[allow(dead_code)]
pub(crate) type PrivateKey = <SigScheme as Scheme>::Private;

/// Bytes of seed the entry points that draw randomness require. It is the whole
/// state of the RNG they seed, so a shorter seed is refused rather than padded.
#[allow(dead_code)]
pub const SEED_LEN: usize = 32;

/// Bytes bincode prepends to a serialized sequence as its length prefix.
#[allow(dead_code)]
pub const VEC_LENGTH: usize = 8;
/// Bytes in a serialized signature, compressed G1.
#[allow(dead_code)]
pub const SIGNATURE_LEN: usize = 48;
/// Bytes in a share index, spelled as a literal because cbindgen evaluates
/// these expressions itself and cannot call `size_of`. The assertion below
/// keeps it tied to `Idx`.
#[allow(dead_code)]
pub const IDX_LEN: usize = 4;
const _: () = assert!(IDX_LEN == std::mem::size_of::<Idx>());

/// Bytes in one serialized partial signature. `combine` splits its flattened
/// input into chunks of this size, so a caller has to build that input to
/// match.
#[allow(dead_code)]
pub const PARTIAL_SIG_LENGTH: usize = VEC_LENGTH + SIGNATURE_LEN + IDX_LEN;
