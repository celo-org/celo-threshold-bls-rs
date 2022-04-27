/*//! # ECIES
//!
//! Implements an Elliptic Curve Integrated Encryption Scheme using SHA256 as the Key Derivation
//! Function.
//!
//! # Examples
//!
//! ```rust
//! use threshold_bls::{
//!     ecies::{encrypt, decrypt},
//!     curve::bls12381::G2Curve,
//!     group::{Curve, Element}
//! };
//!
//! let message = b"hello";
//! let rng = &mut rand::thread_rng();
//! let secret_key = <G2Curve as Curve>::Scalar::rand(rng);
//! let mut public_key = <G2Curve as Curve>::Point::one();
//! public_key.mul(&secret_key);
//!
//! // encrypt the message with the receiver's public key
//! let ciphertext = encrypt::<G2Curve, _>(&public_key, &message[..], rng);
//!
//! // the receiver can then decrypt the ciphertext with their secret key
//! let cleartext = decrypt(&secret_key, &ciphertext).unwrap();
//!
//! assert_eq!(&message[..], &cleartext[..]);
//! ```
*/
use crate::group::{Curve, Element};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

// crypto imports
use chacha20poly1305::{
    aead::{Aead, Error as AError, NewAead},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;

// re-export for usage by dkg primitives
pub use chacha20poly1305::aead::Error as EciesError;

/// The nonce length
const NONCE_LEN: usize = 12;

/// The ephemeral key length
const KEY_LEN: usize = 32;

/// A domain separator
const DOMAIN: [u8; 4] = [1, 9, 6, 9];

/// An ECIES encrypted cipher. Contains the ciphertext's bytes as well as the
/// ephemeral public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesCipher<C: Curve> {
    /// The ciphertext which was encrypted
    aead: Vec<u8>,
    /// The ephemeral public key corresponding to the scalar which was used to
    /// encrypt the plaintext
    ephemeral: C::Point,
    /// The nonce used to encrypt the ciphertext
    nonce: [u8; NONCE_LEN],
}

/// Encrypts the message with a public key (curve point) and returns a ciphertext
pub fn encrypt<C: Curve, R: RngCore>(to: &C::Point, msg: &[u8], rng: &mut R) -> EciesCipher<C> {
    let eph_secret = C::Scalar::rand(rng);

    let mut ephemeral = C::Point::one();
    ephemeral.mul(&eph_secret);

    // dh = eph(yG) = eph * public
    let mut dh = to.clone();
    dh.mul(&eph_secret);

    // derive an ephemeral key from the public key
    let ephemeral_key = derive::<C>(&dh);

    // instantiate the AEAD scheme
    let aead = ChaCha20Poly1305::new(&ephemeral_key.into());

    // generate a random nonce
    let mut nonce: [u8; NONCE_LEN] = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    // do the encryption
    let aead = aead
        .encrypt(&nonce.into(), msg)
        .expect("aead should not fail");

    EciesCipher {
        aead,
        nonce,
        ephemeral,
    }
}

/// Decrypts the message with a secret key (curve scalar) and returns the cleartext
pub fn decrypt<C: Curve>(private: &C::Scalar, cipher: &EciesCipher<C>) -> Result<Vec<u8>, AError> {
    // dh = private * (eph * G) = private * ephPublic
    let mut dh = cipher.ephemeral.clone();
    dh.mul(private);

    let ephemeral_key = derive::<C>(&dh);

    let aead = ChaCha20Poly1305::new(&ephemeral_key.into());

    aead.decrypt(&cipher.nonce.into(), &cipher.aead[..])
}

/// Derives an ephemeral key from the provided public key
fn derive<C: Curve>(dh: &C::Point) -> [u8; KEY_LEN] {
    let serialized = bincode::serialize(dh).expect("could not serialize element");

    // no salt is fine since we use ephemeral - static DH
    let h = Hkdf::<Sha256>::new(None, &serialized);
    let mut ephemeral_key = [0u8; KEY_LEN];
    h.expand(&DOMAIN, &mut ephemeral_key)
        .expect("hkdf should not fail");

    debug_assert!(ephemeral_key.len() == KEY_LEN);

    ephemeral_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12377::{G1Curve as Curve, Scalar, G1};
    use rand::thread_rng;

    fn kp() -> (Scalar, G1) {
        let secret = Scalar::rand(&mut thread_rng());
        let mut public = G1::one();
        public.mul(&secret);
        (secret, public)
    }

    #[test]
    fn test_decryption() {
        let (s1, _) = kp();
        let (s2, p2) = kp();
        let data = vec![1, 2, 3, 4];

        // decryption with the right key OK
        let mut cipher = encrypt::<Curve, _>(&p2, &data, &mut thread_rng());
        let deciphered = decrypt::<Curve>(&s2, &cipher).unwrap();
        assert_eq!(data, deciphered);

        // decrypting with wrong private key should fail
        decrypt::<Curve>(&s1, &cipher).unwrap_err();

        // having an invalid ciphertext should fail
        cipher.aead = vec![0; 32];
        decrypt::<Curve>(&s2, &cipher).unwrap_err();
    }
}
