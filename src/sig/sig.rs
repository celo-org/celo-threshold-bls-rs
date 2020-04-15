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
///  # #[cfg(feature = "bls12_381")]
///  # {
///  use rand::prelude::*;
///  use blind_threshold_bls::{sig::{SignatureScheme,Scheme}, Element, Encodable, Point};
///  use blind_threshold_bls::curve::bls12381::PairingCurve as PC;
///  // import BLS signatures with public keys over G2
///  use blind_threshold_bls::sig::bls::G2Scheme;
///
///
///  let msg = vec![1,9,6,9];
///  let mut msg_point = <G2Scheme::<PC> as Scheme>::Signature::new();
///  msg_point.map(&msg).unwrap();
///  let msg_point_bytes = msg_point.marshal();
///
///  let (private,public) = G2Scheme::<PC>::keypair(&mut thread_rng());
///  let signature = G2Scheme::<PC>::sign(&private,&msg_point_bytes).unwrap();
///  match G2Scheme::<PC>::verify(&public,&msg_point_bytes,&signature) {
///     Ok(_) => println!("signature is correct!"),
///     Err(e) => println!("signature is invalid: {}",e),
///  };
/// # }
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
    fn blind<R: RngCore>(msg: &[u8], rng: &mut R) -> (Self::Token, Vec<u8>);
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
        partial: &[u8],
    ) -> Result<(), Box<dyn Error>>;
    /// Aggregates all partials signature together. Note that this method does
    /// not verify if the partial signatures are correct or not; it only
    /// aggregates them.
    fn aggregate(threshold: usize, partials: &[Partial]) -> Result<Vec<u8>, Box<dyn Error>>;
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>>;
}

/// BlindThreshold is ThresholdScheme that allows to verifiy a partial blinded
/// signature as well blinded message, to aggregate them into one blinded signature
/// such that it can be unblinded after and verified as a regular signature.
pub trait BlindThreshold: ThresholdScheme + Blinder {
    /// unblind_partial takes a blinded partial signatures and removes the blind
    /// component.
    fn unblind_partial(t: &Self::Token, partial: &Partial) -> Result<Partial, Box<dyn Error>>;
}
