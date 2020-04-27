// add this so that we can be more explicit about unsafe calls inside unsafe functions
#![allow(unused_unsafe)]

pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

use threshold_bls::{
    curve::zexe::PairingCurve as Bls12_377,
    sig::{bls::G2Scheme, Scheme},
    Index,
};

pub(crate) type SigScheme = G2Scheme<Bls12_377>;
pub(crate) type PublicKey = <SigScheme as Scheme>::Public;
pub(crate) type PrivateKey = <SigScheme as Scheme>::Private;
pub(crate) type Signature = <SigScheme as Scheme>::Signature;

pub(crate) const VEC_LENGTH: usize = 8;
pub(crate) const SIGNATURE_LEN: usize = 48;
pub(crate) const PUBKEY_LEN: usize = 96;
pub(crate) const PRIVKEY_LEN: usize = 32;
pub(crate) const PARTIAL_SIG_LENGTH: usize =
    VEC_LENGTH + SIGNATURE_LEN + std::mem::size_of::<Index>();
