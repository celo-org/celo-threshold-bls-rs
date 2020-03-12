use crate::group::{Curve, Encodable, Point, Scalar};
use crate::poly::Poly;
use crate::{Index, Public, Share};
use std::error::Error;

pub trait Scheme {
    type Private: Scalar;
    type Public: Point<Self::Private> + Encodable;
    type Signature: Point<Self::Private> + Encodable;
}

pub trait SignatureScheme: Scheme {
    fn sign(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Box<Error>>;
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<Error>>;
}

// TODO: separate -> BlindScheme : Blinder + SignatureScheme
// because blindthreshold scheme unnecessarily exposes "sign"

pub trait Blinder {
    type Token: Encodable;
    fn blind(msg: &[u8]) -> (Self::Token, Vec<u8>);
    fn unblind(t: Self::Token, sig: &[u8]) -> Result<Vec<u8>, Box<Error>>;
}

pub trait BlindScheme: SignatureScheme + Blinder {}

pub type Partial = Vec<u8>;
pub trait ThresholdScheme2: Scheme {
    fn partial_sign(private: &Share<Self::Private>, msg: &[u8]) -> Result<Partial, Box<Error>>;
    fn partial_verify(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partial: &Partial,
    ) -> Result<(), Box<Error>>;
    // XXX Is thre a way to map Vec<Vec<u8>> to &[&[u8]] ?
    fn aggregate(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partials: &[Partial],
    ) -> Result<Vec<u8>, Box<Error>>;
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>>;
    //fn index(p: &Partial) -> Index;
}

pub trait BlindThreshold: ThresholdScheme2 + Blinder {}
