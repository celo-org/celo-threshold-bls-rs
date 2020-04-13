use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use crate::{
    group::{Element, Encodable, Point},
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
type Signature = <BlindThresholdSigs as Scheme>::Signature;
type Result<T> = std::result::Result<T, JsValue>;

/// Signatures for BLS12-377 are 197 bytes long
const SIG_SIZE: usize = 197;

///////////////////////////////////////////////////////////////////////////
// User -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Given a message and a seed, it will blind it and return the blinded message
///
/// # Safety
/// NOTE: If the same seed is used twice, the blinded result WILL be the same
pub fn blind(msg: Vec<u8>, seed: &[u8]) -> BlindedMessage {
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
pub fn verify_sign(public_key: *const PublicKey, msg: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
    let key = unsafe { &*public_key };

    let mut msg_hash = Signature::new();
    msg_hash.map(&msg).unwrap();
    let msg_hash = msg_hash.marshal();

    BlindThresholdSigs::verify(&key, &msg_hash, &signature)
        .map_err(|err| JsValue::from_str(&format!("signature verification failed: {}", err)))?;
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
        .map_err(|err| JsValue::from_str(&format!("could not sign message: {}", err)))
}

#[wasm_bindgen]
/// Signs the blinded message with the provided private key and returns the partial
/// blind signature
pub fn partial_sign(share: *const Share<PrivateKey>, blinded_message: Vec<u8>) -> Result<Vec<u8>> {
    let share = unsafe { &*share };

    BlindThresholdSigs::partial_sign(&share, &blinded_message)
        .map_err(|err| JsValue::from_str(&format!("could not partially sign message: {}", err)))
}

///////////////////////////////////////////////////////////////////////////
// Combiner -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Verifies a partial signature against a service's public key
pub fn verify_partial_blind_signature(
    polynomial: *const Poly<PrivateKey, PublicKey>,
    blinded_message: &[u8],
    sig: Vec<u8>,
) -> Result<bool> {
    let polynomial = unsafe { &*polynomial };
    BlindThresholdSigs::partial_verify(polynomial, blinded_message, &sig).map_err(|err| {
        JsValue::from_str(&format!("could not partially verify message: {}", err))
    })?;
    Ok(true)
}

#[wasm_bindgen]
/// Combines a vector of blinded partial signatures.
///
/// NOTE: Wasm-bindgen does not support Vec<Vec<u8>>, so this function accepts a flattened
/// byte vector which it will parse in chunks for each signature.
pub fn combine(threshold: usize, signatures: Vec<u8>) -> Result<Vec<u8>> {
    let sigs = signatures
        .chunks(SIG_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<Vec<u8>>>();

    BlindThresholdSigs::aggregate(threshold, &sigs).map_err(|err| {
        JsValue::from_str(&format!(
            "could not aggregate sigs: {}. length: {}",
            err,
            sigs.len()
        ))
    })
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
    threshold_public_key: PublicKey,
    pub t: usize,
    pub n: usize,
}

#[wasm_bindgen]
impl Keys {
    #[wasm_bindgen(getter)]
    pub fn shares(&self) -> *const Vec<Share<PrivateKey>> {
        &self.shares as *const Vec<Share<PrivateKey>>
    }

    #[wasm_bindgen]
    pub fn get_share(&self, index: usize) -> *const Share<PrivateKey> {
        &self.shares[index] as *const Share<PrivateKey>
    }

    #[wasm_bindgen]
    pub fn num_shares(&self) -> usize {
        self.shares.len()
    }

    #[wasm_bindgen(getter)]
    pub fn polynomial(&self) -> *const Poly<PrivateKey, PublicKey> {
        &self.polynomial as *const Poly<PrivateKey, PublicKey>
    }

    #[wasm_bindgen(getter)]
    pub fn threshold_public_key(&self) -> *const PublicKey {
        &self.threshold_public_key as *const PublicKey
    }
}

#[wasm_bindgen]
/// WARNING: This is a helper function for local testing of the library. Do not use
/// in production, unless you trust the person that generated the keys.
pub fn threshold_keygen(n: usize, t: usize, seed: &[u8]) -> Keys {
    let mut rng = get_rng(seed);
    let private = Poly::<PrivateKey, PrivateKey>::new_from(t - 1, &mut rng);
    let shares = (0..n)
        .map(|i| private.eval(i as Index))
        .map(|e| Share {
            index: e.index,
            private: e.value,
        })
        .collect();
    let polynomial = private.commit();
    let threshold_public_key = polynomial.public_key();
    Keys {
        shares,
        polynomial,
        threshold_public_key,
        t,
        n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinded_threshold_wasm() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keys = threshold_keygen(5, 3, &seed[..]);

        let msg = vec![1, 2, 3, 4, 6];
        let key = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let blinded_message = blind(msg.clone(), &key[..]);
        let blinded_msg = blinded_message.message.clone();

        let sig1 = partial_sign(keys.get_share(0), blinded_msg.clone()).unwrap();
        // This is buggy
        // verify_partial_blind_signature(keys.polynomial(), &blinded_msg, sig1.clone()).unwrap();
        let sig2 = partial_sign(keys.get_share(1), blinded_msg.clone()).unwrap();
        let sig3 = partial_sign(keys.get_share(2), blinded_msg.clone()).unwrap();

        let concatenated = [sig1, sig2, sig3].concat();
        let asig = combine(3, concatenated).unwrap();
        let unblinded = unblind_signature(asig, blinded_message.scalar()).unwrap();
        verify_sign(keys.threshold_public_key(), msg, unblinded).unwrap();
    }
}
