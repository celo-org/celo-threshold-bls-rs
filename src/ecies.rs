use crate::group::{Curve, Element, Encodable};
use chacha20poly1305::{
    aead,
    aead::{Aead, Error as AError, NewAead},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use rand::prelude::thread_rng;
use rand_core::RngCore;
use sha2::Sha256;
use std::fmt;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug)]
pub struct EciesCipher<C: Curve> {
    aead: Vec<u8>,
    ephemereal: C::Point,
}

impl<C> Clone for EciesCipher<C>
where
    C: Curve,
{
    fn clone(&self) -> Self {
        EciesCipher {
            aead: self.aead.clone(),
            ephemereal: self.ephemereal.clone(),
        }
    }
}

#[derive(Debug)]
pub enum EciesError {
    TooShortCipher(usize, usize),
    InvalidCipher(AError),
}

impl fmt::Display for EciesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use EciesError::*;
        let s = match self {
            TooShortCipher(c, n) => format!("cipher len {} < nonce len {}", c, n),
            InvalidCipher(e) => format!("invalid cipher: {:?}", e),
        };
        write!(f, "{}", s)
    }
}

impl From<aead::Error> for EciesError {
    fn from(e: aead::Error) -> Self {
        EciesError::InvalidCipher(e)
    }
}

fn derive(dh: &[u8]) -> [u8; KEY_LEN] {
    // no salt is fine since we use ephemereal - static DH
    let h = Hkdf::<Sha256>::new(None, dh);
    let info = vec![1, 9, 6, 9];
    let mut fkey = [0u8; KEY_LEN];
    h.expand(&info, &mut fkey).expect("hkdf should not fail");
    assert!(fkey.len() == KEY_LEN);
    fkey
}

fn encrypt_data(dh: &[u8], data: &[u8]) -> Vec<u8> {
    let fkey = derive(dh);
    let mut nonce: [u8; NONCE_LEN] = [0u8; NONCE_LEN];
    thread_rng().fill_bytes(&mut nonce);
    let aead = ChaCha20Poly1305::new(fkey.into());
    let mut cipher = aead
        .encrypt(&nonce.into(), &data[..])
        .expect("aead should not fail");
    cipher.append(&mut nonce.to_vec());
    cipher
}

fn decrypt_data(dh: &[u8], cipher: &[u8]) -> Result<Vec<u8>, EciesError> {
    if cipher.len() < NONCE_LEN {
        return Err(EciesError::TooShortCipher(cipher.len(), NONCE_LEN));
    }
    let fkey = derive(dh);
    let mut nonce: [u8; NONCE_LEN] = [0u8; NONCE_LEN];
    let from = cipher.len() - NONCE_LEN;
    let to = cipher.len();
    nonce.copy_from_slice(&cipher[from..to]);
    let aead = ChaCha20Poly1305::new((fkey).into());
    let encrypted = &cipher[..from];
    // TODO Why does the From trait does not kick-in automatically ?
    aead.decrypt(&nonce.into(), encrypted)
        .map_err(|e| EciesError::from(e))
}

pub fn encrypt_with<C: Curve>(
    to: &C::Point,
    msg: &[u8],
    mut rng: &mut dyn RngCore,
) -> EciesCipher<C>
where
    C::Point: Encodable,
{
    let mut eph_secret = C::Scalar::new();
    eph_secret.pick(&mut rng);
    let mut eph_public = C::Point::one();
    eph_public.mul(&eph_secret);
    // dh = eph(yG) = eph * public
    let mut dh = to.clone();
    dh.mul(&eph_secret);
    let cipher = encrypt_data(&dh.marshal(), msg);
    EciesCipher {
        aead: cipher,
        ephemereal: eph_public,
    }
}

pub fn decrypt<C: Curve>(
    private: &C::Scalar,
    cipher: &EciesCipher<C>,
) -> Result<Vec<u8>, EciesError>
where
    C::Point: Encodable,
{
    // dh = private (eph * G) = private * ephPublic
    let mut dh = cipher.ephemereal.clone();
    dh.mul(private);
    decrypt_data(&dh.marshal(), &cipher.aead)
}

pub fn encrypt<C: Curve>(to: &C::Point, msg: &[u8]) -> EciesCipher<C>
where
    C::Point: Encodable,
{
    use rand::prelude::*;
    encrypt_with(to, msg, &mut thread_rng())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::{Curve, Scalar as Sc, G1};

    fn kp() -> (Sc, G1) {
        let mut s1 = Sc::new();
        s1.pick(&mut thread_rng());
        let mut p1 = G1::one();
        p1.mul(&s1);
        (s1, p1)
    }

    #[test]
    fn encrypt() {
        let (s1, _) = kp();
        let (s2, p2) = kp();
        let data = vec![1, 2, 3, 4];
        let mut cipher = encrypt_with::<Curve>(&p2, &data, &mut thread_rng());
        // just trying if clone is working
        assert_eq!(cipher.ephemereal, cipher.clone().ephemereal);

        let deciphered = decrypt::<Curve>(&s2, &cipher).unwrap();
        assert_eq!(data, deciphered);

        // decrypting with other private key should fail
        match decrypt::<Curve>(&s1, &cipher) {
            Ok(d) => assert!(d != data),
            _ => {}
        }
        cipher.aead = vec![0; 32];
        let err = decrypt::<Curve>(&s2, &cipher).unwrap_err();
        assert!(match err {
            EciesError::InvalidCipher(_) => true,
            _ => false,
        });

        cipher.aead = vec![0; NONCE_LEN - 1];
        let err = decrypt::<Curve>(&s2, &cipher).unwrap_err();
        assert!(match err {
            EciesError::TooShortCipher(_, _) => true,
            _ => false,
        });
    }
}
