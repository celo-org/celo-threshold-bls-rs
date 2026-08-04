//! # BLS12-377 WASM Bindings for Blind Threshold Signatures.
use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use threshold_bls::{
    poly::{Idx as Index, Poly},
    serialization,
    sig::{
        BlindScheme, BlindThresholdScheme, Scheme, Share, SignatureScheme, ThresholdScheme, Token,
    },
};

use crate::*;

/// What an exported binding returns: a value, or a JS exception.
type Result<T> = std::result::Result<T, JsValue>;

/// What the fallible half of a binding returns, before the error becomes a JS
/// exception.
///
/// Every failure path lives in an internal `try_*` function returning this, and
/// the exported binding does nothing but convert it. `JsValue::from_str` is a
/// shim that panics without unwinding on non-wasm targets, which is where these
/// tests run, so a test that reached one would abort the process instead of
/// failing — and `#[should_panic]` could not contain it either. Error paths are
/// therefore tested against the `try_*` function.
type TryResult<T> = std::result::Result<T, String>;

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
/// # Throws
///
/// - If the seed is shorter than 32 bytes
/// - If the message cannot be blinded
///
/// # Safety
/// - If the same seed is used twice, the blinded result WILL be the same
pub fn blind(message: Vec<u8>, seed: &[u8]) -> Result<BlindedMessage> {
    try_blind(message, seed).map_err(|err| JsValue::from_str(&err))
}

fn try_blind(message: Vec<u8>, seed: &[u8]) -> TryResult<BlindedMessage> {
    // convert the seed to randomness
    let mut rng = get_rng(seed)?;

    // blind the message with this randomness
    let (blinding_factor, blinded_message) = SigScheme::blind_msg(&message, &mut rng)
        .map_err(|err| format!("could not blind message: {}", err))?;

    // return the message and the blinding_factor used for blinding
    Ok(BlindedMessage {
        message: blinded_message,
        blinding_factor,
    })
}

#[wasm_bindgen]
/// Given a blinded message and a blinding_factor used for blinding, it returns the message
/// unblinded
///
/// * blinded_message: A message which has been blinded or a blind signature
/// * blinding_factor: The blinding_factor used to blind the message
///
/// # Throws
///
/// - If unblinding fails.
pub fn unblind(blinded_signature: &[u8], blinding_factor_buf: &[u8]) -> Result<Vec<u8>> {
    let blinding_factor: Token<PrivateKey> = serialization::deserialize(blinding_factor_buf)
        .map_err(|err| {
            JsValue::from_str(&format!("could not deserialize blinding factor {}", err))
        })?;

    SigScheme::unblind_sig(&blinding_factor, blinded_signature)
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
pub fn verify(public_key_buf: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key: PublicKey = serialization::deserialize(public_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize public key {}", err)))?;

    // checks the signature on the message hash
    SigScheme::verify(&public_key, message, signature)
        .map_err(|err| JsValue::from_str(&format!("signature verification failed: {}", err)))
}

#[wasm_bindgen(js_name = verifyBlindSignature)]
/// Verifies a signature over a message that is already a serialized group
/// point (e.g. a blinded message), without hashing it to the curve.
///
/// Note that this only proves the signature was produced over the given
/// point. It says nothing about the plaintext that was blinded — use
/// `verify` on the unblinded signature and plaintext for that.
///
/// * public_key: The public key used to sign the message
/// * message: The serialized group point which was signed
/// * signature: The signature which was produced on the message
///
/// # Throws
///
/// - If verification fails
pub fn verify_blind_signature(
    public_key_buf: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let public_key: PublicKey = serialization::deserialize(public_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize public key {}", err)))?;

    // checks the pairing against the message point directly, without hashing
    SigScheme::blind_verify(&public_key, message, signature)
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
pub fn sign(private_key_buf: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let private_key: PrivateKey = serialization::deserialize(private_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize private key {}", err)))?;

    SigScheme::sign(&private_key, message)
        .map_err(|err| JsValue::from_str(&format!("could not sign message: {}", err)))
}

#[wasm_bindgen(js_name = signBlindedMessage)]
/// Signs the message with the provided private key without hashing and returns the signature
///
/// # Throws
///
/// - If signing fails
pub fn sign_blinded_message(private_key_buf: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let private_key: PrivateKey = serialization::deserialize(private_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize private key {}", err)))?;

    SigScheme::blind_sign(&private_key, message)
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
pub fn partial_sign(share_buf: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let share: Share<PrivateKey> = serialization::deserialize(share_buf).map_err(|err| {
        JsValue::from_str(&format!("could not deserialize private key share {}", err))
    })?;

    SigScheme::partial_sign(&share, message)
        .map_err(|err| JsValue::from_str(&format!("could not partially sign message: {}", err)))
}

#[wasm_bindgen(js_name = partialSignBlindedMessage)]
/// Signs the message with the provided **share** of the private key and returns the **partial**
/// signature.
///
/// # Throws
///
/// - If signing fails
///
/// NOTE: This method must NOT be called with a PrivateKey which is not generated via a
/// secret sharing scheme.
pub fn partial_sign_blinded_message(share_buf: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let share: Share<PrivateKey> = serialization::deserialize(share_buf).map_err(|err| {
        JsValue::from_str(&format!("could not deserialize private key share {}", err))
    })?;

    SigScheme::sign_blind_partial(&share, message)
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
pub fn partial_verify(polynomial_buf: &[u8], blinded_message: &[u8], sig: &[u8]) -> Result<()> {
    let polynomial: Poly<PublicKey> = serialization::deserialize(polynomial_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize polynomial {}", err)))?;

    SigScheme::partial_verify(&polynomial, blinded_message, sig)
        .map_err(|err| JsValue::from_str(&format!("could not partially verify message: {}", err)))
}

#[wasm_bindgen(js_name = partialVerifyBlindSignature)]
/// Verifies a partial *blind* signature against the public key corresponding to the secret shared
/// polynomial.
///
/// # Throws
///
/// - If verification fails
pub fn partial_verify_blind_signature(
    polynomial_buf: &[u8],
    blinded_message: &[u8],
    sig: &[u8],
) -> Result<()> {
    let polynomial: Poly<PublicKey> = serialization::deserialize(polynomial_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize polynomial {}", err)))?;

    SigScheme::verify_blind_partial(&polynomial, blinded_message, sig)
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
        .chunks(PARTIAL_SIG_LENGTH)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<Vec<u8>>>();

    SigScheme::aggregate(threshold, &sigs)
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
/// # Throws
///
/// - If the threshold is not between 1 and `n`
/// - If the seed is shorter than 32 bytes
pub fn threshold_keygen(n: usize, t: usize, seed: &[u8]) -> Result<Keys> {
    try_threshold_keygen(n, t, seed).map_err(|err| JsValue::from_str(&err))
}

fn try_threshold_keygen(n: usize, t: usize, seed: &[u8]) -> TryResult<Keys> {
    // A polynomial of degree `t - 1` is what makes `t` shares reconstruct the
    // secret, so a threshold of zero has no polynomial to ask for: it would
    // underflow to a degree of `usize::MAX`. A threshold above `n` cannot be
    // met by the shares this deals out.
    if t < 1 || t > n {
        return Err(format!("threshold must be between 1 and {} (got {})", n, t));
    }

    let mut rng = get_rng(seed)?;
    let private = Poly::<PrivateKey>::new_from(t - 1, &mut rng);
    let shares = (0..n)
        .map(|i| private.eval(i as Index))
        .map(|e| Share {
            index: e.index,
            private: e.value,
        })
        .collect();
    let polynomial = private.commit();
    Ok(Keys {
        shares,
        polynomial,
        t,
        n,
    })
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

    #[wasm_bindgen(getter, js_name = blindingFactor)]
    pub fn blinding_factor(&self) -> Vec<u8> {
        bincode::serialize(&self.blinding_factor).expect("could not serialize blinding factor")
    }
}

// Named `WasmKeypair` rather than `Keypair` because `ffi.rs` exports a struct
// by that name too. cbindgen does not evaluate features, so it parses both
// modules and would emit the typedef twice — legal in C11, an error in C99.
// `js_name` keeps the JS class called `Keypair`, which the published
// declarations promise.
#[wasm_bindgen(js_name = Keypair)]
#[derive(Clone)]
/// A BLS12-377 Keypair
pub struct WasmKeypair {
    /// The private key
    private: PrivateKey,
    /// The public key
    public: PublicKey,
}

// Need to implement custom getters if we want to return more than one value
// and expose it https://rustwasm.github.io/wasm-bindgen/reference/attributes/on-rust-exports/getter-and-setter.html
#[wasm_bindgen(js_class = Keypair)]
impl WasmKeypair {
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> Vec<u8> {
        bincode::serialize(&self.private).expect("could not serialize private key")
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        bincode::serialize(&self.public).expect("could not serialize public key")
    }
}

/// Generates a single private key from the provided seed.
///
/// # Throws
///
/// - If the seed is shorter than 32 bytes
#[wasm_bindgen]
pub fn keygen(seed: Vec<u8>) -> Result<WasmKeypair> {
    try_keygen(seed).map_err(|err| JsValue::from_str(&err))
}

fn try_keygen(seed: Vec<u8>) -> TryResult<WasmKeypair> {
    let mut rng = get_rng(&seed)?;
    let (private, public) = SigScheme::keypair(&mut rng);
    Ok(WasmKeypair { private, public })
}

#[wasm_bindgen]
pub struct Keys {
    shares: Vec<Share<PrivateKey>>,
    polynomial: Poly<PublicKey>,
    pub t: usize,
    pub n: usize,
}

impl Keys {
    fn try_get_share(&self, index: usize) -> TryResult<Vec<u8>> {
        let share = self
            .shares
            .get(index)
            .ok_or_else(|| format!("no share at index {}", index))?;

        bincode::serialize(share).map_err(|err| format!("could not serialize share: {}", err))
    }
}

#[wasm_bindgen]
impl Keys {
    /// Returns the share dealt to the holder at `index`, serialized.
    ///
    /// # Throws
    ///
    /// - If there is no share at that index. `numShares` is the bound.
    #[wasm_bindgen(js_name = getShare)]
    pub fn get_share(&self, index: usize) -> Result<Vec<u8>> {
        self.try_get_share(index)
            .map_err(|err| JsValue::from_str(&err))
    }

    #[wasm_bindgen(js_name = numShares)]
    pub fn num_shares(&self) -> usize {
        self.shares.len()
    }

    #[wasm_bindgen(getter, js_name = polynomial)]
    pub fn polynomial(&self) -> Vec<u8> {
        bincode::serialize(&self.polynomial).expect("could not serialize polynomial")
    }

    #[wasm_bindgen(getter, js_name = thresholdPublicKey)]
    pub fn threshold_public_key(&self) -> Vec<u8> {
        bincode::serialize(&self.polynomial.public_key())
            .expect("could not serialize threshold public key")
    }
}

fn get_rng(digest: &[u8]) -> TryResult<impl RngCore> {
    let seed = from_slice(digest)?;
    Ok(ChaChaRng::from_seed(seed))
}

/// Takes the RNG's whole seed from the caller's bytes.
///
/// A shorter seed is refused rather than padded: the padding is not secret, so
/// the key material would be drawn from less randomness than the caller
/// supplied bytes for.
fn from_slice(bytes: &[u8]) -> TryResult<[u8; SEED_LEN]> {
    let mut array = [0; SEED_LEN];
    let seed = bytes.get(..SEED_LEN).ok_or_else(|| {
        format!(
            "seed must be at least {} bytes (got {})",
            SEED_LEN,
            bytes.len()
        )
    })?;
    array.copy_from_slice(seed);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_wasm() {
        threshold_wasm_should_blind(true);
        threshold_wasm_should_blind(false);
    }

    #[test]
    fn signing() {
        wasm_should_blind(true);
        wasm_should_blind(false);
    }

    // The negative tests below call the `try_*` functions rather than the
    // exported bindings, because the conversion the bindings do would abort the
    // test process. See `TryResult`.

    // A seed shorter than the RNG's state used to be sliced to length, which
    // panicked, and a panic in wasm poisons the instance it happened in.
    #[test]
    fn a_short_seed_is_rejected() {
        let short = [7u8; SEED_LEN - 1];

        assert!(try_keygen(short.to_vec()).is_err());
        assert!(try_blind(vec![1, 2, 3], &short).is_err());
        assert!(try_threshold_keygen(5, 3, &short).is_err());
        assert!(try_keygen(Vec::new()).is_err());
    }

    // The whole seed is consumed, so the exact length is enough: the check is
    // not off by one in the other direction.
    #[test]
    fn a_seed_of_exactly_the_required_length_is_accepted() {
        let seed = [7u8; SEED_LEN];

        assert!(try_keygen(seed.to_vec()).is_ok());
        assert!(try_blind(vec![1, 2, 3], &seed).is_ok());
        assert!(try_threshold_keygen(5, 3, &seed).is_ok());
    }

    // A threshold of zero asked for a polynomial of degree `usize::MAX`.
    #[test]
    fn a_threshold_outside_1_to_n_is_rejected() {
        let seed = [7u8; SEED_LEN];

        assert!(try_threshold_keygen(5, 0, &seed).is_err());
        assert!(try_threshold_keygen(5, 6, &seed).is_err());
        assert!(try_threshold_keygen(0, 0, &seed).is_err());
        assert!(try_threshold_keygen(5, 1, &seed).is_ok());
        assert!(try_threshold_keygen(5, 5, &seed).is_ok());
    }

    // `numShares` is the caller's only guard, and it was advisory.
    #[test]
    fn a_share_index_past_the_last_share_is_rejected() {
        let keys = try_threshold_keygen(5, 3, &[7u8; SEED_LEN]).unwrap();
        assert_eq!(keys.num_shares(), 5);

        assert!(keys.try_get_share(4).is_ok());
        assert!(keys.try_get_share(5).is_err());
        assert!(keys.try_get_share(usize::MAX).is_err());
    }

    fn wasm_should_blind(should_blind: bool) {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keypair = keygen(seed.to_vec()).unwrap();

        let msg = vec![1, 2, 3, 4, 6];
        let key = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let (message, token) = if should_blind {
            let ret = blind(msg.clone(), &key[..]).unwrap();
            (ret.message.clone(), ret.blinding_factor())
        } else {
            (msg.clone(), vec![])
        };

        let sign_fn = if should_blind {
            sign_blinded_message
        } else {
            sign
        };

        let sig = sign_fn(&keypair.private_key(), &message).unwrap();

        if should_blind {
            verify_blind_signature(&keypair.public_key(), &message, &sig).unwrap();
            let unblinded = unblind(&sig, &token).unwrap();
            verify(&keypair.public_key(), &msg, &unblinded).unwrap();
        } else {
            verify(&keypair.public_key(), &msg, &sig).unwrap();
        }
    }

    fn threshold_wasm_should_blind(should_blind: bool) {
        let (n, t) = (5, 3);
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keys = threshold_keygen(n, t, &seed[..]).unwrap();

        let msg = vec![1, 2, 3, 4, 6];
        let key = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let (message, token) = if should_blind {
            let ret = blind(msg.clone(), &key[..]).unwrap();
            (ret.message.clone(), ret.blinding_factor())
        } else {
            (msg.clone(), vec![])
        };

        let sign_fn = if should_blind {
            partial_sign_blinded_message
        } else {
            partial_sign
        };

        let verify_fn = if should_blind {
            partial_verify_blind_signature
        } else {
            partial_verify
        };

        let sigs = (0..t)
            .map(|i| sign_fn(&keys.get_share(i).unwrap(), &message).unwrap())
            .collect::<Vec<Vec<_>>>();

        sigs.iter()
            .for_each(|sig| verify_fn(&keys.polynomial(), &message, sig).unwrap());

        let concatenated = sigs.concat();
        let asig = combine(3, concatenated).unwrap();

        if should_blind {
            verify_blind_signature(&keys.threshold_public_key(), &message, &asig).unwrap();
            let unblinded = unblind(&asig, &token).unwrap();
            verify(&keys.threshold_public_key(), &msg, &unblinded).unwrap();
        } else {
            verify(&keys.threshold_public_key(), &msg, &asig).unwrap();
        }
    }
}
