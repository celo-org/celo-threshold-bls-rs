pub use super::tbls::Share; // import and re-export it for easier access
use crate::{
    group::{Element, Point, Scalar},
    poly::Poly,
};
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};

/// The `Scheme` trait contains the basic information of the groups over
/// which the signing operations takes places and a way to create a valid key
/// pair.
///
/// The Scheme trait is necessary to implement for "simple" signature scheme as
/// well for threshold based signature scheme.
pub trait Scheme: Debug {
    /// `Private` represents the field over which private keys are represented.
    type Private: Scalar<RHS = Self::Private>;
    /// `Public` represents the group over which the public keys are
    /// represented.
    type Public: Point<RHS = Self::Private> + Serialize + DeserializeOwned;
    /// `Signature` represents the group over which the signatures are reresented.
    type Signature: Point<RHS = Self::Private> + Serialize + DeserializeOwned;

    /// Returns a new fresh keypair usable by the scheme.
    fn keypair<R: RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let private = Self::Private::rand(rng);

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
///  use threshold_bls::{sig::{SignatureScheme, Scheme, G2Scheme}, group::{Element, Point}};
///  use threshold_bls::curve::bls12381::PairingCurve as PC;
///
///  let msg = vec![1,9,6,9];
///  let (private,public) = G2Scheme::<PC>::keypair(&mut thread_rng());
///  let signature = G2Scheme::<PC>::sign(&private,&msg).unwrap();
///  match G2Scheme::<PC>::verify(&public, &msg, &signature) {
///     Ok(_) => println!("signature is correct!"),
///     Err(e) => println!("signature is invalid: {}",e),
///  };
/// # }
/// ```
/// Note signature scheme handles the format of the signature itself.
pub trait SignatureScheme: Scheme {
    /// Error produced when signing a message
    type Error: Error;

    /// Signs the message with the provided private key and returns a serialized signature
    fn sign(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies that the signature on the provided message was produced by the public key
    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error>;
}

/*/// BlindScheme is a signature scheme where the message can be blinded before
/// signing so the signer does not know the real message. The signature can
/// later be "unblinded" as to reveal a valid signature over the initial
/// message.
///
/// ```
///  # #[cfg(feature = "bls12_381")]
///  # {
///  use rand::prelude::*;
///  use threshold_bls::{
///     sig::{BlindScheme,SignatureScheme, Scheme, G2Scheme},
///     group::{Element, Point}
///  };
///  use threshold_bls::curve::bls12381::PairingCurve as PC;
///
///  let msg = vec![1,9,6,9];
///  let (private,public) = G2Scheme::<PC>::keypair(&mut thread_rng());
///  // we first blind the message so the signers don't know the real underlying
///  // message they are signing.
///  let (token, blinded_msg) = G2Scheme::<PC>::blind_msg(&msg,&mut thread_rng());
///  // this method is called by the signers, that sign blindly.
///  let blinded_sig = G2Scheme::<PC>::blind_sign(&private,&blinded_msg).unwrap();
///  // this method can be called by a third party that is able to verify if a
///  // blinded signature is a a valid one even without having access to the
///  // clear message.
///  G2Scheme::<PC>::blind_verify(&public,&blinded_msg,&blinded_sig)
///        .expect("blinded signatures should be correct");

///  // the owner of the message can then unblind the signature to reveal a
///  // regular signature that can be verified using the regular method of the
///  // SignatureScheme.
///  let clear_sig = G2Scheme::<PC>::unblind_sig(&token,&blinded_sig).unwrap();
///  match G2Scheme::<PC>::verify(&public, &msg, &clear_sig) {
///     Ok(_) => println!("signature is correct!"),
///     Err(e) => println!("signature is invalid: {}",e),
///  };
/// # }
/// ```*/
pub trait BlindScheme: Scheme {
    /// The blinding factor which will be used to unblind the message
    type Token: Serialize + DeserializeOwned;

    /// Error during blinding or unblinding
    type Error: Error;

    /// Blinds the provided message using randomness from the provided RNG and returns
    /// the blinding factor and the blinded message.
    fn blind_msg<R: RngCore>(msg: &[u8], rng: &mut R) -> (Self::Token, Vec<u8>);

    /// Given the blinding factor that was used to blind the provided message, it will
    /// unblind it and return the cleartext message
    fn unblind_sig(t: &Self::Token, blinded_message: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// blind_sign is the method that signs the given blinded message and
    /// returns a blinded signature.
    fn blind_sign(private: &Self::Private, blinded_msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// blind_verify takes the blinded message and the blinded signature and
    /// checks if the latter is a valid signature by the provided public key. One must then unblind the signature so
    /// it can be verified using the regular `SignatureScheme::verify` method.
    fn blind_verify(
        public: &Self::Public,
        blinded_msg: &[u8],
        blinded_sig: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Partial is simply an alias to denote a partial signature.
pub type Partial = Vec<u8>;

/// ThresholdScheme is a threshold-based `t-n` signature scheme. The security of
/// such a scheme means at least `t` participants are required produce a "partial
/// signature" to then produce a regular signature.
/// The `dkg-core` module allows participants to create a distributed private/public key
/// that can be used with implementations `ThresholdScheme`.
pub trait ThresholdScheme: Scheme {
    /// Error produced when partially signing, aggregating or verifying
    type Error: Error;

    /// Partially signs a message with a share of the private key
    fn partial_sign(private: &Share<Self::Private>, msg: &[u8]) -> Result<Partial, Self::Error>;

    /// Verifies a partial signature on a message against the public polynomial
    fn partial_verify(
        public: &Poly<Self::Public>,
        msg: &[u8],
        partial: &[u8],
    ) -> Result<(), Self::Error>;

    /// Aggregates all partials signature together. Note that this method does
    /// not verify if the partial signatures are correct or not; it only
    /// aggregates them.
    fn aggregate(threshold: usize, partials: &[Partial]) -> Result<Vec<u8>, Self::Error>;
}

/// BlindThreshold is ThresholdScheme that allows to verify a partially blinded
/// signature as well blinded message, to aggregate them into one blinded signature
/// such that it can be unblinded after and verified as a regular signature.
pub trait BlindThresholdScheme: BlindScheme {
    type Error: Error;

    /// sign_blind_partial partially signs a blinded message and returns a
    /// partial blind signature over it.
    fn sign_blind_partial(
        private: &Share<Self::Private>,
        blinded_msg: &[u8],
    ) -> Result<Partial, <Self as BlindThresholdScheme>::Error>;

    /// Given the blinding factor that was used to blind a message that was blind partially
    /// signed, it will unblind it and return the cleartext signature
    fn unblind_partial_sig(
        t: &Self::Token,
        partial: &[u8],
    ) -> Result<Partial, <Self as BlindThresholdScheme>::Error>;

    /// verify_blind_partial checks if a given blinded partial signature is
    /// correct given the blinded message. This can be called by any third party
    /// given the two parameters which are not private (since they are blinded).
    fn verify_blind_partial(
        public: &Poly<Self::Public>,
        blind_msg: &[u8],
        blind_partial: &[u8],
    ) -> Result<(), <Self as BlindThresholdScheme>::Error>;
}
