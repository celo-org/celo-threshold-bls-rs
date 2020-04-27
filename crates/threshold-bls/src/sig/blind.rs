use crate::group::{Element, Point, Scalar};
use crate::sig::{BlindScheme, Blinder, SignatureScheme, SignatureSchemeExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// BlindError are a type of errors that blind signature scheme can return.
#[derive(Debug, Error)]
pub enum BlinderError {
    /// InvalidToken is thrown out when the token used to unblind can not be
    /// inversed. This error should not happen if you use the Token that was
    /// returned by the blind operation.
    #[error("invalid token")]
    InvalidToken,
    #[error("could not deserialize: {0}")]
    BincodeError(#[from] bincode::Error),
}

/// Blinding a message before requesting a signature requires the usage of a
/// private blinding factor that is called a Token. To unblind the signature
/// afterwards, one needs the same token as what the blinding method returned.
/// In this blind signature scheme, the token is simply a field element.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "S: Serialize + serde::de::DeserializeOwned")]
pub struct Token<S: Scalar>(S);

impl<S: Scalar> Token<S> {
    pub fn new() -> Self {
        Self(S::new())
    }
}

// We implement Blinder for anything that implements Signature scheme, so we also
// enable the BlindScheme for all these, for convenience
impl<I> BlindScheme for I where I: SignatureSchemeExt {}

/// The blinder follows the protocol described
/// in this [paper](https://eprint.iacr.org/2018/733.pdf).
impl<I: SignatureScheme> Blinder for I {
    type Token = Token<I::Private>;
    type Error = BlinderError;

    fn blind<R: RngCore>(msg: &[u8], rng: &mut R) -> (Self::Token, Vec<u8>) {
        let r = I::Private::rand(rng);

        let mut h = I::Signature::new();

        // r * H(m)
        // XXX result from zexe API but it shouldn't
        h.map(msg).expect("could not map to the group");
        h.mul(&r);

        let serialized = bincode::serialize(&h).expect("serialization should not fail");
        (Token(r), serialized)
    }

    fn unblind(t: &Self::Token, sigbuff: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut sig: I::Signature = bincode::deserialize(sigbuff)?;

        // r^-1 * ( r * H(m)^x) = H(m)^x
        let ri = t.0.inverse().ok_or(BlinderError::InvalidToken)?;
        sig.mul(&ri);

        let serialized = bincode::serialize(&sig)?;
        Ok(serialized)
    }
}

#[cfg(test)]
#[cfg(feature = "bls12_381")]
mod tests {
    use super::*;
    use crate::curve::bls12381::PairingCurve as PCurve;
    use crate::sig::bls::{G1Scheme, G2Scheme};
    use rand::thread_rng;

    #[test]
    fn blind_g1() {
        blind_test::<G1Scheme<PCurve>>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn blind_g2() {
        blind_test::<G2Scheme<PCurve>>();
    }

    fn blind_test<B>()
    where
        B: BlindScheme,
    {
        let (private, public) = B::keypair(&mut thread_rng());
        let msg = vec![1, 9, 6, 9];

        let (token, blinded) = B::blind(&msg, &mut thread_rng());

        // signs the blinded message w/o hashing
        let blinded_sig = B::sign_without_hashing(&private, &blinded).unwrap();

        let clear_sig = B::unblind(&token, &blinded_sig).expect("unblind should go well");

        B::verify(&public, &msg, &clear_sig).unwrap();
    }
}
