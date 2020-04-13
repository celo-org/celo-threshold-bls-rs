use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use crate::{
    curve::zexe::PairingCurve as Bls12_377,
    sig::{
        blind::{BG1Scheme, Token},
        tblind::G1Scheme,
        Blinder, Scheme, SignatureScheme, ThresholdScheme,
    },
};

type BlindThresholdSigs = G1Scheme<Bls12_377>;
type BlindSigs = BG1Scheme<Bls12_377>;
type PublicKey = <BlindThresholdSigs as Scheme>::Public;
type PrivateKey = <BlindThresholdSigs as Scheme>::Private;
type Result<T> = std::result::Result<T, JsValue>;

///////////////////////////////////////////////////////////////////////////
// User -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Given a message and a seed, it will blind it and return the blinded message
///
/// # Safety
/// NOTE: If the same seed is used twice, the blinded result WILL be the same
pub fn blind(msg: Vec<u8>, seed: Vec<u8>) -> BlindedMessage {
    let mut rng = get_rng(&seed);
    let (scalar, blinded_message) = BlindThresholdSigs::blind(&msg, &mut rng);

    BlindedMessage {
        message: blinded_message,
        scalar,
    }
}

/// Given a blinded signature and the scalar used to blind the original message, it will return the
/// unblinded signature
///
/// If unmarshalling the scalar or unblinding the signature errored, it will return an empty
/// vector
#[wasm_bindgen]
pub fn unblind_signature(
    blinded_msg: Vec<u8>,
    scalar: *const Token<PrivateKey>,
) -> Result<Vec<u8>> {
    let scalar = unsafe { &*scalar };

    BlindThresholdSigs::unblind(&scalar, &blinded_msg)
        .map_err(|_| JsValue::from_str("could not unblind signature"))
}

#[wasm_bindgen]
/// Verifies the signature after it has been unblinded. Users will call this on the
/// threshold signature against the full public key
pub fn verify_sign(
    public_key: *const PublicKey,
    msg: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool> {
    let key = unsafe { &*public_key };

    BlindThresholdSigs::verify(&key, &msg, &signature)
        .map_err(|_| JsValue::from_str("signature verifiaction failed"))?;
    Ok(true)
}

///////////////////////////////////////////////////////////////////////////
// Service -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Signs the blinded message with the provided private key and returns the partial
/// blind signature
pub fn sign(private_key: *const PrivateKey, blinded_message: Vec<u8>) -> Result<Vec<u8>> {
    let key = unsafe { &*private_key };

    BlindSigs::sign(&key, &blinded_message)
        .map_err(|_| JsValue::from_str("could not sign message"))
}

#[wasm_bindgen]
/// Signs the blinded message with the provided private key and returns the partial
/// blind signature
pub fn partial_sign(share: *const Share<PrivateKey>, blinded_message: Vec<u8>) -> Result<Vec<u8>> {
    let share = unsafe { &*share };

    BlindThresholdSigs::partial_sign(&share, &blinded_message)
        .map_err(|_| JsValue::from_str("could not partially sign message"))
}

///////////////////////////////////////////////////////////////////////////
// Combiner -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Verifies a partial signature against a service's public key
pub fn verify_partial_blind_signature(_signature: Vec<u8>, _public_key: Vec<u8>) -> bool {
    unimplemented!()
}

#[wasm_bindgen]
/// Combines a vector of blinded partial signatures.
///
/// NOTE: Wasm-bindgen does not support Vec<Vec<u8>>, so this function accepts a flattened
/// byte vector which it will parse in 48 byte chunks for each signature.
pub fn combine(_signature: Vec<u8>) -> Vec<u8> {
    unimplemented!()
}

///////////////////////////////////////////////////////////////////////////
// Helpers
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen(inspectable)]
/// A blinded message along with the scalar used to produce it
pub struct BlindedMessage {
    /// The resulting blinded message
    message: Vec<u8>,
    /// The scalar which was used to generate the blinded message. This will be used
    /// to unblind the signature received on the blinded message to a valid signature
    /// on the unblinded message
    scalar: Token<PrivateKey>,
}

#[wasm_bindgen]
impl BlindedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn scalar(&self) -> *const Token<PrivateKey> {
        &self.scalar as *const Token<PrivateKey>
    }
}

fn get_rng(digest: &[u8]) -> impl RngCore {
    let seed = from_slice(digest);
    ChaChaRng::from_seed(seed)
}

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

#[wasm_bindgen]
#[derive(Clone)]
/// A BLS12-377 Keypair
pub struct Keypair {
    /// The private key
    private: PrivateKey,
    /// The public key
    public: PublicKey,
}

// Need to implement custom getters if we want to return more than one value
// and expose it https://rustwasm.github.io/wasm-bindgen/reference/attributes/on-rust-exports/getter-and-setter.html
#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter)]
    pub fn private(&self) -> *const PrivateKey {
        &self.private as *const PrivateKey
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> *const PublicKey {
        &self.public as *const PublicKey
    }
}

/// Generates a single private key
#[wasm_bindgen]
pub fn keygen(seed: Vec<u8>) -> Keypair {
    // wasm_bindgen requires fully qualified syntax
    let mut rng = get_rng(&seed);
    let (private, public) = BlindThresholdSigs::keypair(&mut rng);
    Keypair { private, public }
}

use crate::{poly::Poly, Index, Share};

#[wasm_bindgen]
pub struct Keys {
    shares: Vec<Share<PrivateKey>>,
    polynomial: Poly<PrivateKey, PublicKey>,
}

#[wasm_bindgen]
impl Keys {
    #[wasm_bindgen(getter)]
    pub fn shares(&self) -> Vec<u8> {
        let _s = self.shares.clone();
        vec![]
    }

    #[wasm_bindgen(getter)]
    pub fn polynomial(&self) -> Vec<u64> {
        let _s = self.polynomial.clone();
        vec![]
    }
}

#[wasm_bindgen]
pub fn threshold_keygen(n: usize, t: usize) -> Keys {
    let private = Poly::<PrivateKey, PrivateKey>::new(t - 1);
    let shares = (0..n)
        .map(|i| private.eval(i as Index))
        .map(|e| Share {
            index: e.index,
            private: e.value,
        })
        .collect();
    Keys {
        shares,
        polynomial: private.commit(),
    }
}
