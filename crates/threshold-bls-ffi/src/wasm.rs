//! # BLS12-377 WASM Bindings for Blind Threshold Signatures.
use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use threshold_bls::{
    curve::zexe::PairingCurve as Bls12_377,
    group::{Element, Encodable},
    poly::Poly,
    sig::{
        blind::Token, bls::G2Scheme, Blinder, Scheme, SignatureScheme, ThresholdScheme,
        ThresholdSchemeExt,
    },
    Index, Share,
};

type SigScheme = G2Scheme<Bls12_377>;
type PublicKey = <SigScheme as Scheme>::Public;
type PrivateKey = <SigScheme as Scheme>::Private;
type Signature = <SigScheme as Scheme>::Signature;
type Result<T> = std::result::Result<T, JsValue>;

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
    let (blinding_factor, blinded_message) = SigScheme::blind(&message, &mut rng);

    // return the message and the blinding_factor used for blinding
    BlindedMessage {
        message: blinded_message,
        blinding_factor,
    }
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
    let mut blinding_factor = Token::<PrivateKey>::new();
    blinding_factor
        .unmarshal(blinding_factor_buf)
        .map_err(|err| {
            JsValue::from_str(&format!("could not unmarshal blinding factor {}", err))
        })?;

    SigScheme::unblind(&blinding_factor, blinded_signature)
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
    let mut public_key = PublicKey::new();
    public_key
        .unmarshal(&public_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not unmarshal public key {}", err)))?;

    // checks the signature on the message hash
    <SigScheme as SignatureScheme>::verify(&public_key, &message, &signature)
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
    let mut private_key = PrivateKey::new();
    private_key
        .unmarshal(&private_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not unmarshal private key {}", err)))?;

    SigScheme::sign(&private_key, &message)
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
    let mut share = Share::<PrivateKey>::new(0, PrivateKey::new());
    share.unmarshal(&share_buf).map_err(|err| {
        JsValue::from_str(&format!("could not unmarshal private key share {}", err))
    })?;

    SigScheme::partial_sign(&share, &message)
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
    let mut share = Share::<PrivateKey>::new(0, PrivateKey::new());
    share.unmarshal(&share_buf).map_err(|err| {
        JsValue::from_str(&format!("could not unmarshal private key share {}", err))
    })?;

    SigScheme::partial_sign_without_hashing(&share, &message)
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
    let mut polynomial = Poly::<PrivateKey, PublicKey>::from(vec![]);
    polynomial
        .unmarshal(&polynomial_buf)
        .map_err(|err| JsValue::from_str(&format!("could not unmarshal polynomial {}", err)))?;

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
    let mut polynomial = Poly::<PrivateKey, PublicKey>::from(vec![]);
    polynomial
        .unmarshal(&polynomial_buf)
        .map_err(|err| JsValue::from_str(&format!("could not unmarshal polynomial {}", err)))?;

    SigScheme::partial_verify_without_hashing(&polynomial, blinded_message, sig)
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
        .chunks(Signature::marshal_len() + std::mem::size_of::<Index>())
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
    Keys {
        shares,
        polynomial,
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

    #[wasm_bindgen(getter, js_name = blindingFactor)]
    pub fn blinding_factor(&self) -> Vec<u8> {
        self.blinding_factor.marshal()
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
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private.marshal()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.marshal()
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
    let (private, public) = SigScheme::keypair(&mut rng);
    Keypair { private, public }
}

#[wasm_bindgen]
pub struct Keys {
    shares: Vec<Share<PrivateKey>>,
    polynomial: Poly<PrivateKey, PublicKey>,
    pub t: usize,
    pub n: usize,
}

#[wasm_bindgen]
impl Keys {
    #[wasm_bindgen(js_name = getShare)]
    pub fn get_share(&self, index: usize) -> Vec<u8> {
        self.shares[index].marshal()
    }

    #[wasm_bindgen(js_name = numShares)]
    pub fn num_shares(&self) -> usize {
        self.shares.len()
    }

    #[wasm_bindgen(getter, js_name = polynomial)]
    pub fn polynomial(&self) -> Vec<u8> {
        self.polynomial.marshal()
    }

    #[wasm_bindgen(getter, js_name = thresholdPublicKey)]
    pub fn threshold_public_key(&self) -> Vec<u8> {
        self.polynomial.public_key().marshal()
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
    fn threshold_wasm() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keys = threshold_keygen(5, 3, &seed[..]);

        let msg = vec![1, 2, 3, 4, 6];

        let sig1 = partial_sign(&keys.get_share(0), &msg).unwrap();
        let sig2 = partial_sign(&keys.get_share(1), &msg).unwrap();
        let sig3 = partial_sign(&keys.get_share(2), &msg).unwrap();

        partial_verify(&keys.polynomial(), &msg, &sig1).unwrap();
        partial_verify(&keys.polynomial(), &msg, &sig2).unwrap();
        partial_verify(&keys.polynomial(), &msg, &sig3).unwrap();

        let concatenated = [sig1, sig2, sig3].concat();
        let asig = combine(3, concatenated).unwrap();

        verify(&keys.threshold_public_key(), &msg, &asig).unwrap();
    }

    #[test]
    fn blinded_threshold_wasm() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keys = threshold_keygen(5, 3, &seed[..]);

        let msg = vec![1, 2, 3, 4, 6];
        let key = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let blinded_message = blind(msg.clone(), &key[..]);
        let blinded_msg = blinded_message.message.clone();

        let sig1 = partial_sign_blinded_message(&keys.get_share(0), &blinded_msg).unwrap();
        let sig2 = partial_sign_blinded_message(&keys.get_share(1), &blinded_msg).unwrap();
        let sig3 = partial_sign_blinded_message(&keys.get_share(2), &blinded_msg).unwrap();

        partial_verify_blind_signature(&keys.polynomial(), &blinded_msg, &sig1).unwrap();
        partial_verify_blind_signature(&keys.polynomial(), &blinded_msg, &sig2).unwrap();
        partial_verify_blind_signature(&keys.polynomial(), &blinded_msg, &sig3).unwrap();

        let concatenated = [sig1, sig2, sig3].concat();
        let asig = combine(3, concatenated).unwrap();

        let unblinded = unblind(&asig, &blinded_message.blinding_factor()).unwrap();

        verify(&keys.threshold_public_key(), &msg, &unblinded).unwrap();
    }
}
