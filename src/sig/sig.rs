use crate::group::{Element, Encodable, Point, Scalar};
use crate::poly::Poly;
use crate::Share;
use rand_core::RngCore;
use std::error::Error;

/// The `Scheme` trait contains the basic information of the groups over
/// which the signing operations takes places and a way to create a valid key
/// pair.
///
/// The Scheme trait is necessary to implement for "simple" signature scheme as
/// well for threshold based signature scheme.
pub trait Scheme {
    /// `Private` represents the field over which private keys are represented.
    type Private: Scalar;
    /// `Public` represents the group over which the public keys are
    /// represented.
    type Public: Point<Self::Private> + Encodable;
    /// `Signature` represents the group over which the signatures are reresented.
    type Signature: Point<Self::Private> + Encodable;

    /// Returns a new fresh keypair usable by the scheme.
    fn keypair<R: RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let mut private = Self::Private::new();
        private.pick(rng);
        let mut public = Self::Public::one();
        public.mul(&private);
        (private, public)
    }
}

/// SignatureScheme is the trait that defines the operations of a sinature
/// scheme, namely `sign` and `verify`. Below is an example of using the
/// signature scheme based on BLS, using the BLS12-381 curves.
///
/// ```
///  use rand::prelude::*;
///  use threshold::sig::{SignatureScheme,Scheme};
///  use threshold::curve::bls12381::PairingCurve as PC;
///  // import BLS signatures with public keys over G2
///  use threshold::sig::bls::G2Scheme;
///
///
///  let message = vec![1,9,6,9];
///  let (private,public) = G2Scheme::<PC>::keypair(&mut thread_rng());
///  let signature = G2Scheme::<PC>::sign(&private,&message).unwrap();
///  match G2Scheme::<PC>::verify(&public,&message,&signature) {
///     Ok(_) => println!("signature is correct!"),
///     Err(e) => println!("signature is invalid: {}",e),
///  };
/// ```
/// Note signature scheme handles the format of the signature itself.
pub trait SignatureScheme: Scheme {
    fn sign(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>>;
}

/// Blinder holds the functionality of blinding and unblinding a message. It is
/// not to be used alone but in combination with a signature scheme or a
/// threshold scheme.
pub trait Blinder {
    type Token: Encodable;
    fn blind(msg: &[u8]) -> (Self::Token, Vec<u8>);
    fn unblind(t: &Self::Token, sig: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

/// BlindScheme is a signature scheme where the message can be blinded before
/// signature so the signer does not know the real message. The signature can
/// later be "unblinded" as to reveal a valid signature over the initial
/// message.
pub trait BlindScheme: SignatureScheme + Blinder {}

/// Partial is simply an alias to denote a partial signature.
pub type Partial = Vec<u8>;

/// ThresholdScheme is a threshold-based `t-n` signature scheme. The security of
/// such a scheme means at least `t` participants are required produce a "partial
/// signature" to then produce a regular signature.
/// The `dkg` module allows participants to create a distributed private/public key
/// that can be used with implementations `ThresholdScheme`.
pub trait ThresholdScheme: Scheme {
    fn partial_sign(private: &Share<Self::Private>, msg: &[u8]) -> Result<Partial, Box<dyn Error>>;
    fn partial_verify(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partial: &Partial,
    ) -> Result<(), Box<dyn Error>>;
    fn aggregate(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partials: &[Partial],
    ) -> Result<Vec<u8>, Box<dyn Error>>;
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>>;
    //fn index(p: &Partial) -> Index;
}

pub trait BlindThreshold: ThresholdScheme + Blinder {}
