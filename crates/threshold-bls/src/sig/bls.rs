use crate::group::{Element, Encodable, PairingCurve};
use crate::sig::{Scheme, SignatureScheme};
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
        ) -> Result<Vec<u8>, BLSError<Self::Signature>> {
            let mut h = Self::Signature::new();
            h.unmarshal(msg).map_err(BLSError::EncodableError)?;
            h.mul(private);

            Ok(h.marshal())
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
            T::internal_sign(private, msg)
        }

        /// Verifies the signature by the provided public key **on the message's hash**.
        fn verify(
            public: &Self::Public,
            msg_bytes: &[u8],
            sig_bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let mut sig = Self::Signature::new();
            sig.unmarshal(sig_bytes).map_err(BLSError::EncodableError)?;

            let mut hm = Self::Signature::new();
            hm.unmarshal(msg_bytes).map_err(BLSError::EncodableError)?;

            let success = T::final_exp(public, &sig, &hm);
            if !success {
                return Err(BLSError::InvalidSig);
            }

            Ok(())
        }

    }

}

/// G1Scheme implements the BLS signature scheme with G1 as private / public
/// keys and G2 as signature elements over the given pairing curve.
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
    use crate::group::{Encodable, Point};
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
        let mut msg_point = <G2Scheme<PCurve> as Scheme>::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();
        let sig = G2Scheme::<PCurve>::sign(&private, &msg_point_bytes).unwrap();
        G2Scheme::<PCurve>::verify(&public, &msg_point_bytes, &sig)
            .expect("that should not happen");
    }

    #[test]
    fn nbls_g1() {
        let (private, public) = g1_pair();
        let msg = vec![1, 9, 6, 9];
        let mut msg_point = <G1Scheme<PCurve> as Scheme>::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();
        let sig = G1Scheme::<PCurve>::sign(&private, &msg_point_bytes).unwrap();
        G1Scheme::<PCurve>::verify(&public, &msg_point_bytes, &sig)
            .expect("that should not happen");
    }
}
