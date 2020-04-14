//! # BLS12-377 WASM Bindings for Blind Threshold Signatures.
use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use crate::{
    curve::zexe::PairingCurve as Bls12_377,
    group::{Element, Encodable, Point},
    poly::Poly,
    sig::{
        blind::{BG1Scheme, Token},
        tblind::G1Scheme,
        Blinder, Scheme, SignatureScheme, ThresholdScheme,
    },
    Index, Share,
};

// TODO(gakonst): Make these bindings more generic. Maybe a macro is needed here since
// wasm-bindgen does not support generics
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
/// * message: A cleartext message which you want to blind
/// * seed: A 32 byte seed for randomness. You can get one securely via `crypto.randomBytes(32)`
///
/// Returns a `BlindedMessage`. The `BlindedMessage.blinding_factor` should be saved for unblinding any
/// signatures on `BlindedMessage.message`
///
/// # Safety
/// - If the same seed is used twice, the blinded result WILL be the same
pub fn blind(message: Vec<u8>, seed: &[u8]) -> BlindedMessage {
    // convert the seed to randomness
    let mut rng = get_rng(&seed);

    // blind the message with this randomness
    let (blinding_factor, blinded_message) = BlindThresholdSigs::blind(&message, &mut rng);

    // return the message and the blinding_factor used for blinding
    BlindedMessage {
        message: blinded_message,
        blinding_factor,
    }
}

#[wasm_bindgen]
/// Given a blinded message and a pointer to the blinding_factor used for blinding, it returns the message
/// unblinded
///
/// * blinded_message: A message which has been blinded or a blind signature
/// * blinding_factor: The blinding_factor used to blind the message
///
/// # Throws
///
/// - If unblinding fails.
///
/// # Safety
///
/// - The `blinding_factor` is a pointer. If an invalid pointer value is given, this will panic.
pub fn unblind(
    blinded_signature: &[u8],
    blinding_factor: *const Token<PrivateKey>,
) -> Result<Vec<u8>> {
    // SAFETY: Must be given a valid pointer to the blinding_factor.
    let blinding_factor = unsafe { &*blinding_factor };

    BlindThresholdSigs::unblind(&blinding_factor, blinded_signature)
        .map_err(|err| JsValue::from_str(&format!("could not unblind signature {}", err)))
}

#[wasm_bindgen]
/// Verifies the signature after it has been unblinded. Users will call this on the
/// threshold signature against the full public key
///
/// * public_key: The public key used to sign the message
/// * message: The message which was signed
/// * signature: The signature which was produced on the message
///
/// # Throws
///
/// - If verification fails
///
/// # Safety
///
/// - The `public_key` is a pointer. If an invalid pointer value is given, this will panic.
pub fn verify(public_key: *const PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    // SAFETY: Must be given a valid pointer to the public key.
    let key = unsafe { &*public_key };

    // hashes the message
    let mut msg_hash = Signature::new();
    msg_hash.map(&message).unwrap();
    let msg_hash = msg_hash.marshal();

    // checks the signature on the message hash
    BlindThresholdSigs::verify(&key, &msg_hash, &signature)
        .map_err(|err| JsValue::from_str(&format!("signature verification failed: {}", err)))
}

///////////////////////////////////////////////////////////////////////////
// Service -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Signs the message with the provided private key and returns the signature
///
/// # Throws
///
/// - If signing fails
///
/// # Safety
///
/// - The `private_key` is a pointer. If an invalid pointer value is given, this will panic.
pub fn sign(private_key: *const PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: Must be given a valid pointer to the private key
    let key = unsafe { &*private_key };

    BlindSigs::sign(&key, &message)
        .map_err(|err| JsValue::from_str(&format!("could not sign message: {}", err)))
}

#[wasm_bindgen(js_name = partialSign)]
/// Signs the message with the provided **share** of the private key and returns the **partial**
/// signature.
///
/// # Throws
///
/// - If signing fails
///
/// NOTE: This method must NOT be called with a PrivateKey which is not generated via a
/// secret sharing scheme.
///
/// # Safety
/// - The `private_key` is a pointer. If an invalid pointer value is given, this will panic.
pub fn partial_sign(share: *const Share<PrivateKey>, message: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: Must be given a valid pointer to the share
    let share = unsafe { &*share };

    BlindThresholdSigs::partial_sign(&share, &message)
        .map_err(|err| JsValue::from_str(&format!("could not partially sign message: {}", err)))
}

///////////////////////////////////////////////////////////////////////////
// Combiner -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen(js_name = partialVerify)]
/// Verifies a partial signature against the public key corresponding to the secret shared
/// polynomial.
///
/// # Throws
///
/// - If verification fails
///
/// # Safety
/// - The `polynomial` is a pointer. If an invalid pointer value is given, this will panic.
pub fn partial_verify(
    polynomial: *const Poly<PrivateKey, PublicKey>,
    blinded_message: &[u8],
    sig: &[u8],
) -> Result<()> {
    // SAFETY: Must be given a valid pointer to the polynomial
    let polynomial = unsafe { &*polynomial };

    BlindThresholdSigs::partial_verify(polynomial, blinded_message, sig)
        .map_err(|err| JsValue::from_str(&format!("could not partially verify message: {}", err)))
}

#[wasm_bindgen]
/// Combines a flattened vector of partial signatures to a single threshold signature
///
/// NOTE: Wasm-bindgen does not support Vec<Vec<u8>>, so this function accepts a flattened
/// byte vector which it will parse in chunks for each signature.
///
/// NOTE: If you are working with an array of Uint8Arrays In Javascript, the simplest
/// way to flatten them is via:
///
/// ```js
/// function flatten(arr) {
///     return Uint8Array.from(arr.reduce(function(a, b) {
///         return Array.from(a).concat(Array.from(b));
///     }, []));
/// }
/// ```
///
/// # Throws
///
/// - If the aggregation fails
///
/// # Safety
///
/// - This function does not check if the signatures are valid!
pub fn combine(threshold: usize, signatures: Vec<u8>) -> Result<Vec<u8>> {
    // break the flattened vector to a Vec<Vec<u8>> where each element is a serialized signature
    let sigs = signatures
        .chunks(SIG_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<Vec<u8>>>();

    BlindThresholdSigs::aggregate(threshold, &sigs)
        .map_err(|err| JsValue::from_str(&format!("could not aggregate sigs: {}", err,)))
}

///////////////////////////////////////////////////////////////////////////
// Helpers
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen(js_name = thresholdKeygen)]
/// Generates a t-of-n polynomial and private key shares
///
/// # Safety
///
/// WARNING: This is a helper function for local testing of the library. Do not use
/// in production, unless you trust the person that generated the keys.
///
/// The seed MUST be at least 32 bytes long
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

#[wasm_bindgen(inspectable)]
/// A blinded message along with the blinding_factor used to produce it
pub struct BlindedMessage {
    /// The resulting blinded message
    message: Vec<u8>,
    /// The blinding_factor which was used to generate the blinded message. This will be used
    /// to unblind the signature received on the blinded message to a valid signature
    /// on the unblinded message
    blinding_factor: Token<PrivateKey>,
}

#[wasm_bindgen]
impl BlindedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    #[wasm_bindgen(getter, js_name = blindingFactorPtr)]
    pub fn blinding_factor_ptr(&self) -> *const Token<PrivateKey> {
        &self.blinding_factor as *const Token<PrivateKey>
    }
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
    #[wasm_bindgen(getter, js_name = privateKeyPtr)]
    pub fn private_key_ptr(&self) -> *const PrivateKey {
        &self.private as *const PrivateKey
    }

    #[wasm_bindgen(getter, js_name = publicKeyPtr)]
    pub fn public_key_ptr(&self) -> *const PublicKey {
        &self.public as *const PublicKey
    }
}

/// Generates a single private key from the provided seed.
///
/// # Safety
///
/// The seed MUST be at least 32 bytes long
#[wasm_bindgen]
pub fn keygen(seed: Vec<u8>) -> Keypair {
    let mut rng = get_rng(&seed);
    let (private, public) = BlindThresholdSigs::keypair(&mut rng);
    Keypair { private, public }
}

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
    #[wasm_bindgen(getter, js_name = sharesPtr)]
    pub fn shares(&self) -> *const Vec<Share<PrivateKey>> {
        &self.shares as *const Vec<Share<PrivateKey>>
    }

    #[wasm_bindgen(js_name = getSharePtr)]
    pub fn get_share_ptr(&self, index: usize) -> *const Share<PrivateKey> {
        &self.shares[index] as *const Share<PrivateKey>
    }

    #[wasm_bindgen(js_name = numShares)]
    pub fn num_shares(&self) -> usize {
        self.shares.len()
    }

    #[wasm_bindgen(getter, js_name = polynomialPtr)]
    pub fn polynomial_ptr(&self) -> *const Poly<PrivateKey, PublicKey> {
        &self.polynomial as *const Poly<PrivateKey, PublicKey>
    }

    #[wasm_bindgen(getter, js_name = thresholdPublicKeyPtr)]
    pub fn threshold_public_key_ptr(&self) -> *const PublicKey {
        &self.threshold_public_key as *const PublicKey
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

        let sig1 = partial_sign(keys.get_share_ptr(0), &blinded_msg).unwrap();
        let sig2 = partial_sign(keys.get_share_ptr(1), &blinded_msg).unwrap();
        let sig3 = partial_sign(keys.get_share_ptr(2), &blinded_msg).unwrap();

        partial_verify(keys.polynomial_ptr(), &blinded_msg, &sig1).unwrap();
        partial_verify(keys.polynomial_ptr(), &blinded_msg, &sig2).unwrap();
        partial_verify(keys.polynomial_ptr(), &blinded_msg, &sig3).unwrap();

        let concatenated = [sig1, sig2, sig3].concat();
        let asig = combine(3, concatenated).unwrap();

        let unblinded = unblind(&asig, blinded_message.blinding_factor_ptr()).unwrap();

        verify(keys.threshold_public_key_ptr(), &msg, &unblinded).unwrap();
    }
}
