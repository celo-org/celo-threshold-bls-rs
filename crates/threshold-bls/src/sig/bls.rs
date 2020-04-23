use crate::group::{Element, Encodable, PairingCurve, Point};
use crate::sig::{Scheme, SignatureScheme, SignatureSchemeExt};
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;

/// BLSError are thrown out when using the BLS signature scheme.
#[derive(Debug, Error)]
pub enum BLSError<E: Encodable + Debug> {
    /// InvalidSig is raised when the validation routine of the BLS algorithm
    /// does not finish successfully,i.e. it is an invalid signature.
    #[error("invalid signature")]
    InvalidSig,

    #[error("could not decode data: {0}")]
    EncodableError(E::Error),

    #[error("could not hash to curve")]
    HashingError,
}

// private module workaround to avoid leaking a private
// trait into a public trait
// see https://github.com/rust-lang/rust/issues/34537
// XXX another way to pull it off without this hack?
mod common {
    use super::*;

    /// BLSScheme is an internal trait that encompasses the common work between a
    /// BLS signature over G1 or G2.
    pub trait BLSScheme: Scheme {
        /// Returns sig = msg^{private}. The message MUST be hashed before this call.
        fn internal_sign(
            private: &Self::Private,
            msg: &[u8],
            should_hash: bool,
        ) -> Result<Vec<u8>, BLSError<Self::Signature>> {
            let mut h = Self::Signature::new();
            if should_hash {
                h.map(msg).map_err(|_| BLSError::HashingError)?;
            } else {
                h.unmarshal(msg).map_err(BLSError::EncodableError)?;
            }
            h.mul(private);

            Ok(h.marshal())
        }

        fn internal_verify(
            public: &Self::Public,
            msg: &[u8],
            sig_bytes: &[u8],
            should_hash: bool,
        ) -> Result<(), BLSError<Self::Signature>> {
            let mut sig = Self::Signature::new();
            sig.unmarshal(sig_bytes).map_err(BLSError::EncodableError)?;

            let mut h = Self::Signature::new();
            if should_hash {
                h.map(msg).map_err(|_| BLSError::HashingError)?;
            } else {
                h.unmarshal(msg).map_err(BLSError::EncodableError)?;
            }

            let success = Self::final_exp(public, &sig, &h);
            if !success {
                return Err(BLSError::InvalidSig);
            }

            return Ok(());
        }

        /// Performs the final exponentiation for the BLS sig scheme
        fn final_exp(p: &Self::Public, sig: &Self::Signature, hm: &Self::Signature) -> bool;
    }

    impl<T> SignatureScheme for T
    where
        T: BLSScheme,
    {
        type Error = BLSError<T::Signature>;

        fn sign(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
            T::internal_sign(private, msg, true)
        }

        /// Verifies the signature by the provided public key
        fn verify(
            public: &Self::Public,
            msg_bytes: &[u8],
            sig_bytes: &[u8],
        ) -> Result<(), Self::Error> {
            T::internal_verify(public, msg_bytes, sig_bytes, true)
        }
    }

    impl<T> SignatureSchemeExt for T
    where
        T: BLSScheme,
    {
        fn sign_without_hashing(
            private: &Self::Private,
            msg: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            T::internal_sign(private, msg, false)
        }

        fn verify_without_hashing(
            public: &Self::Public,
            msg_bytes: &[u8],
            sig_bytes: &[u8],
        ) -> Result<(), Self::Error> {
            T::internal_verify(public, msg_bytes, sig_bytes, false)
        }
    }
}

/// G1Scheme implements the BLS signature scheme with G1 as private / public
/// keys and G2 as signature elements over the given pairing curve.
#[derive(Clone, Debug)]
pub struct G1Scheme<C: PairingCurve> {
    m: PhantomData<C>,
}

impl<C> Scheme for G1Scheme<C>
where
    C: PairingCurve,
{
    type Private = C::Scalar;
    type Public = C::G1;
    type Signature = C::G2;
}

impl<C> common::BLSScheme for G1Scheme<C>
where
    C: PairingCurve,
{
    fn final_exp(p: &Self::Public, sig: &Self::Signature, hm: &Self::Signature) -> bool {
        // e(g1,sig) == e(pub, H(m))
        // e(g1,H(m))^x == e(g1,H(m))^x
        let left = C::pair(&C::G1::one(), &sig);
        let right = C::pair(p, &hm);
        left == right
    }
}

/// G2Scheme implements the BLS signature scheme with G2 as private / public
/// keys and G1 as signature elements over the given pairing curve.
#[derive(Clone, Debug)]
pub struct G2Scheme<C: PairingCurve> {
    m: PhantomData<C>,
}

impl<C> Scheme for G2Scheme<C>
where
    C: PairingCurve,
{
    type Private = C::Scalar;
    type Public = C::G2;
    type Signature = C::G1;
}

impl<C> common::BLSScheme for G2Scheme<C>
where
    C: PairingCurve,
{
    fn final_exp(p: &Self::Public, sig: &Self::Signature, hm: &Self::Signature) -> bool {
        // e(sig,g2) == e(H(m),pub)
        // e(H(m),g2)^x == e(H(m),g2)^x
        let left = C::pair(&sig, &Self::Public::one());
        let right = C::pair(&hm, p);
        left == right
    }
}

#[cfg(feature = "bls12_381")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::{PairingCurve as PCurve, Scalar, G1, G2};
    use rand::prelude::*;

    // TODO: make it one like in tbls
    fn g2_pair() -> (Scalar, G2) {
        let mut private = Scalar::new();
        let mut public = G2::one();
        private.pick(&mut thread_rng());
        public.mul(&private);
        (private, public)
    }

    fn g1_pair() -> (Scalar, G1) {
        let mut private = Scalar::new();
        let mut public = G1::one();
        private.pick(&mut thread_rng());
        public.mul(&private);
        (private, public)
    }

    #[test]
    fn nbls_g2() {
        let (private, public) = g2_pair();
        let msg = vec![1, 9, 6, 9];
        let sig = G2Scheme::<PCurve>::sign(&private, &msg).unwrap();
        G2Scheme::<PCurve>::verify(&public, &msg, &sig).expect("that should not happen");
    }

    #[test]
    fn nbls_g1() {
        let (private, public) = g1_pair();
        let msg = vec![1, 9, 6, 9];
        let sig = G1Scheme::<PCurve>::sign(&private, &msg).unwrap();
        G1Scheme::<PCurve>::verify(&public, &msg, &sig).expect("that should not happen");
    }
}
