// add this so that we can be more explicit about unsafe calls inside unsafe functions
#![allow(unused_unsafe)]

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
pub(crate) const PUBKEY_LEN: usize = 96;
#[cfg(feature = "ffi")]
pub(crate) const PRIVKEY_LEN: usize = 32;

use threshold_bls::{poly::Idx, schemes::bls12_377::G2Scheme as SigScheme, sig::Scheme};

#[allow(dead_code)]
pub(crate) type PublicKey = <SigScheme as Scheme>::Public;
#[allow(dead_code)]
pub(crate) type PrivateKey = <SigScheme as Scheme>::Private;

#[allow(dead_code)]
pub(crate) const VEC_LENGTH: usize = 8;
#[allow(dead_code)]
pub(crate) const SIGNATURE_LEN: usize = 48;
#[allow(dead_code)]
pub(crate) const PARTIAL_SIG_LENGTH: usize =
    VEC_LENGTH + SIGNATURE_LEN + std::mem::size_of::<Idx>();
