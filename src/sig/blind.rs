use crate::group::{Element, Encodable, PairingCurve, Point, Scalar};
use crate::sig::bls::{self, BLSError};
use crate::sig::{BlindScheme, Blinder, Scheme as SScheme, SignatureScheme};
use rand::prelude::thread_rng;
use rand_core::RngCore;
use std::error::Error;
use std::marker::PhantomData;

pub struct Token<S: Scalar>(S);
impl<S> Encodable for Token<S>
where
    S: Scalar,
{
    fn marshal(&self) -> Vec<u8> {
        self.0.marshal()
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        self.0.unmarshal(data)
    }
}
// https://eprint.iacr.org/2018/733.pdf
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
    fn sign(private: &Self::Private, blinded: &[u8]) -> Result<Vec<u8>, Box<Error>> {
        let mut hm = I::Signature::new();
        match hm.unmarshal(blinded) {
            Ok(()) => {
                hm.mul(private);
                Ok(hm.marshal())
            }
            Err(e) => Err(e),
        }
    }
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<Error>> {
        I::verify(public, msg, sig)
    }
}

impl<I> Blinder for Scheme<I>
where
    I: SignatureScheme,
{
    type Token = Token<I::Private>;
    fn blind(msg: &[u8]) -> (Self::Token, Vec<u8>) {
        let mut r = I::Private::new();
        r.pick(&mut thread_rng());
        let mut h = I::Signature::new();
        // r * H(m)
        h.map(msg);
        h.mul(&r);
        (Token(r), h.marshal())
    }
    fn unblind(t: Self::Token, sigbuff: &[u8]) -> Result<Vec<u8>, Box<Error>> {
        let mut sig = I::Signature::new();
        if let Err(_) = sig.unmarshal(sigbuff) {
            return Err(Box::new(BLSError::InvalidPoint));
        }
        match t.0.inverse() {
            Some(ri) => {
                // r^-1 * ( r * H(m)^x) = H(m)^x
                sig.mul(&ri);
                Ok(sig.marshal())
            }
            None => Err(Box::new(BLSError::InvalidBlindingFactor)),
        }
    }
}

impl<I> BlindScheme for Scheme<I> where I: SignatureScheme {}

pub enum BlindError {
    InvalidBlindedMessage,
    InvalidToken,
    BLSError,
}

/*pub fn blind_from<C: PairingCurve>(msg: &[u8], rng: &mut impl RngCore) -> (Token<C>, Vec<u8>)*/
//where
//C::G1: Encodable,
//{
//let mut r = C::Scalar::new();
//r.pick(&mut thread_rng());
//let mut h = C::G1::new();
//// r * H(m)
//h.map(msg);
//h.mul(&r);
//(Token(r), h.marshal())
//}
//pub fn blind<C: PairingCurve>(msg: &[u8]) -> (Token<C>, Vec<u8>)
//where
//C::G1: Encodable,
//{
//use rand::prelude::*;
//blind_from(msg, &mut thread_rng())
//}

//pub fn sign<C: PairingCurve>(private: &C::Scalar, blinded_msg: &[u8]) -> Result<Vec<u8>, BLSError>
//where
//C::G1: Encodable,
//{
//let mut bm = C::G1::new();
//if let Err(_) = bm.unmarshal(blinded_msg) {
//return Err(BLSError::InvalidBlindedMessage);
//}
//bm.mul(private);
//Ok(bm.marshal())
//}

///// move occurs here as this blinding factor should not be kept around.
//pub fn unblind<C: PairingCurve>(factor: Token<C>, signature: &[u8]) -> Result<Vec<u8>, BLSError>
//where
//C::G1: Encodable,
//{
//let mut sig = C::G1::new();
//if let Err(_) = sig.unmarshal(signature) {
//return Err(BLSError::InvalidPoint);
//}
//match factor.0.inverse() {
//Some(ri) => {
//// r^-1 * ( r * H(m)^x) = H(m)^x
//sig.mul(&ri);
//Ok(sig.marshal())
//}
//None => Err(BLSError::InvalidBlindingFactor),
//}
//}

pub type BG2Scheme<C> = Scheme<bls::G2Scheme<C>>;
pub type BG1Scheme<C> = Scheme<bls::G1Scheme<C>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::{PairingCurve as PCurve, Scalar, G1, G2};
    use crate::sig::bls;
    use rand::prelude::*;

    fn pair<B: SignatureScheme>() -> (B::Private, B::Public) {
        let mut private = B::Private::new();
        let mut public = B::Public::one();
        private.pick(&mut thread_rng());
        public.mul(&private);
        (private, public)
    }

    #[test]
    fn blind_g1() {
        blind_test::<BG1Scheme<PCurve>>();
    }

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
        let (token, blinded) = B::blind(&msg);
        let blinded_sig = B::sign(&private, &blinded).unwrap();
        let clear_sig = B::unblind(token, &blinded_sig).expect("unblind should go well");
        match B::verify(&public, &msg, &clear_sig) {
            Ok(()) => {}
            Err(e) => {
                println!("{:?}", e);
                assert!(false);
            }
        }
    }
}
