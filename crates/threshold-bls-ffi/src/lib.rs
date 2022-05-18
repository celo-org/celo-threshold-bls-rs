// add this so that we can be more explicit about unsafe calls inside unsafe functions
#![allow(unused_unsafe)]

extern crate cfg_if;

cfg_if::cfg_if! {
    if #[cfg(feature = "wasm")] {
        pub mod wasm;
    } else {
        pub mod ffi;
        pub(crate) type Signature = <SigScheme as Scheme>::Signature;
        pub(crate) const PUBKEY_LEN: usize = 96;
        pub(crate) const PRIVKEY_LEN: usize = 32;
    }
}

use threshold_bls::{poly::Idx, schemes::bls12_377::G2Scheme as SigScheme, sig::Scheme};

pub(crate) type PublicKey = <SigScheme as Scheme>::Public;
pub(crate) type PrivateKey = <SigScheme as Scheme>::Private;

pub(crate) const VEC_LENGTH: usize = 8;
pub(crate) const SIGNATURE_LEN: usize = 48;
pub(crate) const PARTIAL_SIG_LENGTH: usize =
    VEC_LENGTH + SIGNATURE_LEN + std::mem::size_of::<Idx>();

use bls_crypto::{hashers::DirectHasher, Hasher};
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RNGError {
    #[error("could not hash digest correctly")]
    HashError(#[from] bls_crypto::BLSError),

    #[error("The length of seed bytes is not long enough")]
    LengthError,
}

fn get_rng(digest: &[u8]) -> Result<impl RngCore, RNGError> {
    let mut seed = digest;
    if digest.len() > 32 {
        let hash = DirectHasher
            .hash(b"BLS_RNG", digest, 32)?;
        seed = &hash.to_vec();
    }

    let res = match from_slice(seed) {
        Ok(bytes) => Ok(ChaChaRng::from_seed(bytes)),
        Err(e) => Err(e),
    };
    res
}

fn from_slice(bytes: &[u8]) -> Result<[u8; 32], RNGError> {
    let mut array = [0; 32];
    if bytes.len() < 32 {
        return Err(RNGError::LengthError);
    }
    let bytes = &bytes[..array.len()]; // Make sure there is enough data
    array.copy_from_slice(bytes);
    Ok(array)
}
