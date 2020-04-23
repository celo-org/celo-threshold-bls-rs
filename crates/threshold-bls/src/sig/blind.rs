use crate::group::{Element, Encodable, Point, Scalar};
use crate::sig::{BlindScheme, Blinder, SignatureScheme};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// BlindError are a type of errors that blind signature scheme can return.
#[derive(Debug, Error)]
pub enum BlinderError<E: Encodable + std::fmt::Debug> {
    /// InvalidToken is thrown out when the token used to unblind can not be
    /// inversed. This error should not happen if you use the Token that was
    /// returned by the blind operation.
    #[error("invalid token")]
    InvalidToken,
    #[error("could not deserialize scalar: {0}")]
    EncodableError(E::Error),
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

impl<S: Scalar> Encodable for Token<S> {
    type Error = <S as Encodable>::Error;

    fn marshal_len() -> usize {
        <S as Encodable>::marshal_len()
    }
    fn marshal(&self) -> Vec<u8> {
        self.0.marshal()
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.0.unmarshal(data)
    }
}

// We implement BlindScheme for anything that is both a blinder and a scheme. We
// don't take a regular Signature since the signing process isn't the same
impl<B> BlindScheme for B where B: Blinder + Scheme  {
    fn sign(private: &Self::Private, blinded: &[u8]) -> Result<Vec<u8>, Self::Error> {
    let mut hm = I::Signature::new();
        match hm.unmarshal(blinded) {
            Ok(()) => {
                hm.mul(private);
                Ok(hm.marshal())
            }
            Err(e) => Err(e),
        }

    }
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error> {
        I::verify(public,msg,sig)
    }
}

/// The blinder follows the protocol described
/// in this [paper](https://eprint.iacr.org/2018/733.pdf).
impl<I: SignatureScheme> Blinder for I {
    type Token = Token<I::Private>;
    type Error = BlinderError<I::Signature>;

    fn blind<R: RngCore>(msg: &[u8], rng: &mut R) -> (Self::Token, Vec<u8>) {
        let mut r = I::Private::new();
        r.pick(rng);

        let mut h = I::Signature::new();

        // r * H(m)
        // XXX result from zexe API but it shouldn't
        h.map(msg).expect("could not map to the group");
        h.mul(&r);

        (Token(r), h.marshal())
    }

    fn unblind(t: &Self::Token, sigbuff: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut sig = I::Signature::new();
        sig.unmarshal(sigbuff)
            .map_err(BlinderError::EncodableError)?;

        // r^-1 * ( r * H(m)^x) = H(m)^x
        let ri = t.0.inverse().ok_or(BlinderError::InvalidToken)?;
        sig.mul(&ri);

        Ok(sig.marshal())
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
        let blinded_sig = B::sign(&private, &blinded).unwrap();
        let clear_sig = B::unblind(&token, &blinded_sig).expect("unblind should go well");

        let mut msg_point = B::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();

        B::verify(&public, &msg_point_bytes, &clear_sig).unwrap();
    }
}
