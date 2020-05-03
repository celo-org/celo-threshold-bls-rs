//pub use super::tbls::Share; // import and re-export it for easier access
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

/// Extension trait over `SignatureScheme` which provides signing & verification methods
/// which do not hash the message.
pub trait SignatureSchemeExt: SignatureScheme {
    /// Signs the message with the provided private key and returns a serialized signature. This
    /// method **will not** hash the message before signing it. It should be used for
    /// blind-signature related functionalities. In other cases, prefer `Signature`
    fn sign_without_hashing(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies that the signature on the provided message was produced by the public key.
    /// This method **will not** h the message. It should be used when verifying blind signatures
    /// by parties that do not have access to the blinding factor
    fn verify_without_hashing(
        public: &Self::Public,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Self::Error>;
}

/// BlindScheme is a signature scheme where the message can be blinded before
/// signature so the signer does not know the real message. The signature can
/// later be "unblinded" as to reveal a valid signature over the initial
/// message.
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

    fn blind_sign(private: &Self::Private, blinded_msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error>;
    fn blind_verify(public: &Self::Public, blinded_msg: &[u8], blinded_sig: &[u8]) -> Result<(), Self::Error>;
}
/*/// Partial is simply an alias to denote a partial signature.*/
//pub type Partial = Vec<u8>;

///// ThresholdScheme is a threshold-based `t-n` signature scheme. The security of
///// such a scheme means at least `t` participants are required produce a "partial
///// signature" to then produce a regular signature.
///// The `dkg-core` module allows participants to create a distributed private/public key
/*/// that can be used with implementations `ThresholdScheme`.*/
/*pub trait ThresholdScheme: Scheme {*/
    ///// Error produced when partially signing, aggregating or verifying
    //type Error: Error;

    ///// Partially signs a message with a share of the private key
    //fn partial_sign(private: &Share<Self::Private>, msg: &[u8]) -> Result<Partial, Self::Error>;

    ///// Verifies a partial signature on a message against the public polynomial
    //fn partial_verify(
        //public: &Poly<Self::Public>,
        //msg: &[u8],
        //partial: &[u8],
    //) -> Result<(), Self::Error>;

    ///// Aggregates all partials signature together. Note that this method does
    ///// not verify if the partial signatures are correct or not; it only
    ///// aggregates them.
    //fn aggregate(threshold: usize, partials: &[Partial]) -> Result<Vec<u8>, Self::Error>;

    ///// Verifies a threshold signature on a message against the public key which corresponds
    ///// to the public polynomial of the shares that produced the partial signatures
    //fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error>;
//}

///// Extension trait over `ThresholdScheme` which provides partial signing & verification methods
///// which do not hash the message.
//pub trait ThresholdSchemeExt: ThresholdScheme {
    ///// Partially signs a message with a share of the private key **without hashing the message**
    //fn partial_sign_without_hashing(
        //private: &Share<Self::Private>,
        //msg: &[u8],
    //) -> Result<Partial, Self::Error>;

    ///// Verifies a partial signature on a message against the public polynomial **without hashing
    ///// the message**
    //fn partial_verify_without_hashing(
        //public: &Poly<Self::Public>,
        //msg: &[u8],
        //partial: &[u8],
    //) -> Result<(), Self::Error>;
//}

///// BlindThreshold is ThresholdScheme that allows to verify a partially blinded
///// signature as well blinded message, to aggregate them into one blinded signature
///// such that it can be unblinded after and verified as a regular signature.
//pub trait BlindThresholdScheme: ThresholdSchemeExt + Blinder {
    //type Error: Error;

    ///// Given the blinding factor that was used to blind a message that was blind partially
    ///// signed, it will unblind it and return the cleartext signature
    //fn unblind_partial(
        //t: &Self::Token,
        //partial: &[u8],
    //) -> Result<Partial, <Self as BlindThresholdScheme>::Error>;
/*}*/
