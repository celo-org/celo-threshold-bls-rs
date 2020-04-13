use crate::group::{Element, Encodable, Point, Scalar};
use crate::sig::bls::{self, BLSError};
use crate::sig::{BlindScheme, Blinder, Scheme as SScheme, SignatureScheme};
use rand::RngCore;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;

/// Blinding a message before requesting a signature requires the usage of a
/// private blinding factor that is called a Token. To unblind the signature
/// afterwards, one needs the same token as what the blinding method returned.
/// In this blind signature scheme, the token is simply a field element.
pub struct Token<S: Scalar>(S);

impl<S> Encodable for Token<S>
where
    S: Scalar,
{
    fn marshal_len() -> usize {
        <S as Encodable>::marshal_len()
    }
    fn marshal(&self) -> Vec<u8> {
        self.0.marshal()
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        self.0.unmarshal(data)
    }
}
/// Scheme implements the signature scheme interface as well as the blinder
/// interface to provide a blind signature scheme. It follows the protocol described
/// in this [paper](https://eprint.iacr.org/2018/733.pdf).
pub struct Scheme<I: SignatureScheme> {
    i: PhantomData<I>,
}

impl<I> SScheme for Scheme<I>
where
    I: SignatureScheme,
{
    type Private = I::Private;
    type Public = I::Public;
    type Signature = I::Signature;
}

// XXX Why can't I implement just for any T<I> ?
impl<I> SignatureScheme for Scheme<I>
where
    I: SignatureScheme,
{
    fn sign(private: &Self::Private, blinded: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hm = I::Signature::new();
        match hm.unmarshal(blinded) {
            Ok(()) => {
                hm.mul(private);
                Ok(hm.marshal())
            }
            Err(e) => Err(e),
        }
    }
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>> {
        I::verify(public, msg, sig)
    }
}

impl<I> Blinder for Scheme<I>
where
    I: SignatureScheme,
{
    type Token = Token<I::Private>;

    fn blind<R: RngCore>(msg: &[u8], rng: &mut R) -> (Self::Token, Vec<u8>) {
        let mut r = I::Private::new();
        r.pick(rng);

        let mut h = I::Signature::new();

        // r * H(m)
        // XXX result from zexe API but it shouldn't
        h.map(msg).unwrap();
        h.mul(&r);
        (Token(r), h.marshal())
    }

    fn unblind(t: &Self::Token, sigbuff: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut sig = I::Signature::new();
        if let Err(_) = sig.unmarshal(sigbuff) {
            return Err(Box::new(BlindError::SigError(BLSError::InvalidPoint)));
        }
        match t.0.inverse() {
            Some(ri) => {
                // r^-1 * ( r * H(m)^x) = H(m)^x
                sig.mul(&ri);
                Ok(sig.marshal())
            }
            None => Err(Box::new(BlindError::InvalidToken)),
        }
    }
}

impl<I> BlindScheme for Scheme<I> where I: SignatureScheme {}

/// BlindError are a type of errors that blind signature scheme can return.
#[derive(Debug)]
pub enum BlindError {
    /// InvalidToken is thrown out when the token used to unblind can not be
    /// inversed. This error should not happen if you use the Token that was
    /// returned by the blind operation.
    InvalidToken,
    /// BLS errors are thrown out by the currently implemented scheme since it
    /// uses BLS verification routines underneath.
    SigError(BLSError),
}

/// BG2Scheme is a blind signature scheme implementation that operates with
/// private/public key pairs over G1 and signatures over G2 using the
/// parametrized pairing curve.
pub type BG2Scheme<C> = Scheme<bls::G2Scheme<C>>;
/// BG1Scheme is a blind signature scheme implementation that operates with
/// private/public key pairs over G2 and signatures over G1 using the
/// parametrized pairing curve.
pub type BG1Scheme<C> = Scheme<bls::G1Scheme<C>>;

impl fmt::Display for BlindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlindError::InvalidToken => write!(f, "invalid token"),
            BlindError::SigError(e) => write!(f, "BLS error: {}", e),
        }
    }
}

impl Error for BlindError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            BlindError::InvalidToken => None,
            BlindError::SigError(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "bls12_381")]
    use crate::curve::bls12381::PairingCurve as PCurve;
    use rand::thread_rng;

    fn pair<B: SignatureScheme>() -> (B::Private, B::Public) {
        let mut private = B::Private::new();
        let mut public = B::Public::one();
        private.pick(&mut thread_rng());
        public.mul(&private);
        (private, public)
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn blind_g1() {
        blind_test::<BG1Scheme<PCurve>>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn blind_g2() {
        blind_test::<BG2Scheme<PCurve>>();
    }

    fn blind_test<B>()
    where
        B: BlindScheme,
    {
        let (private, public) = pair::<B>();
        let msg = vec![1, 9, 6, 9];
        let (token, blinded) = B::blind(&msg, &mut thread_rng());
        let blinded_sig = B::sign(&private, &blinded).unwrap();
        let clear_sig = B::unblind(&token, &blinded_sig).expect("unblind should go well");
        let mut msg_point = B::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();
        match B::verify(&public, &msg_point_bytes, &clear_sig) {
            Ok(()) => {}
            Err(e) => {
                println!("{:?}", e);
                assert!(false);
            }
        }
    }
}
