use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use crate::{
    curve::zexe::PairingCurve as Bls12_377,
    group::{Element, Encodable},
    sig::{
        blind::{BG1Scheme, Token},
        Blinder, Scheme, SignatureScheme,
    },
};

type BlindSigs = BG1Scheme<Bls12_377>;

///////////////////////////////////////////////////////////////////////////
// User -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Given a message and a seed, it will blind it and return the blinded message
///
/// # Safety
/// NOTE: If the same seed is used twice, the blinded result WILL be the same
pub fn blind(msg: Vec<u8>, seed: Vec<u8>) -> BlindedMessage {
    // an RNG is obtained from the provided seed and is used to blind the msg
    let mut rng = get_rng(&seed);
    let (scalar, blinded_message) = BlindSigs::blind(&msg, &mut rng);
    BlindedMessage {
        message: blinded_message,
        scalar: scalar.marshal(),
    }
}

/// Given a blinded signature and the scalar used to blind the original message, it will return the
/// unblinded signature
///
/// If unmarshalling the scalar or unblinding the signature errored, it will return an empty
/// vector
#[wasm_bindgen]
pub fn unblind_signature(blinded_msg: Vec<u8>, scalar_buf: Vec<u8>) -> Vec<u8> {
    let mut scalar = Token::new();
    if let Err(_) = scalar.unmarshal(&scalar_buf) {
        return vec![];
    }

    match BlindSigs::unblind(&scalar, &blinded_msg) {
        Ok(res) => res,
        Err(_) => vec![],
    }
}

#[wasm_bindgen]
/// Verifies the signature after it has been unblinded
pub fn verify_sign(public_key: Vec<u8>, msg: Vec<u8>, signature: Vec<u8>) -> bool {
    // wasm-bindgen cannot understand this type if inlined
    type Public = <BlindSigs as Scheme>::Public;
    let mut key = Public::new();
    if let Err(_) = key.unmarshal(&public_key) {
        return false;
    }

    match BlindSigs::verify(&key, &msg, &signature) {
        Ok(_) => true,
        Err(_) => false,
    }
}

///////////////////////////////////////////////////////////////////////////
// Service -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Signs the blinded message with the provided private key and returns the partial
/// blind signature
pub fn sign(private_key: Vec<u8>, blinded_message: Vec<u8>) -> Vec<u8> {
    let mut key = <<BlindSigs as Scheme>::Private as Element>::new();
    key.unmarshal(&private_key)
        .expect("could not deserialize private key");

    BlindSigs::sign(&key, &blinded_message).expect("could not sign blinded message")
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
    scalar: Vec<u8>,
}

#[wasm_bindgen]
impl BlindedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn scalar(&self) -> Vec<u8> {
        self.scalar.clone()
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
    private: Vec<u8>,
    /// The public key
    public: Vec<u8>,
}

// Need to implement custom getters if we want to return more than one value
// and expose it https://rustwasm.github.io/wasm-bindgen/reference/attributes/on-rust-exports/getter-and-setter.html
#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter)]
    pub fn private(&self) -> Vec<u8> {
        self.private.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

/// Generates a private key
#[wasm_bindgen]
pub fn keygen(seed: Vec<u8>) -> Keypair {
    // wasm_bindgen requires fully qualified syntax
    let mut rng = get_rng(&seed);
    let (private, public) = BlindSigs::keypair(&mut rng);
    Keypair {
        private: private.marshal(),
        public: public.marshal(),
    }
}
