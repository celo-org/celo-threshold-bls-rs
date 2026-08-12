use crate::group::{Element, PairingCurve, Point};
use crate::serialization;
use crate::sig::{Scheme, SignatureScheme};
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;

/// BLSError are thrown out when using the BLS signature scheme.
#[derive(Debug, Error)]
pub enum BLSError {
    /// InvalidSig is raised when the validation routine of the BLS algorithm
    /// does not finish successfully,i.e. it is an invalid signature.
    #[error("invalid signature")]
    InvalidSig,

    /// InvalidPublicKey is raised when the public key is the identity element,
    /// which would accept an identity signature on any message.
    #[error("public key is the identity element")]
    InvalidPublicKey,

    /// InvalidMessagePoint is raised when the message point is the identity
    /// element, which would let an identity signature verify under any key.
    #[error("message point is the identity element")]
    InvalidMessagePoint,

    #[error("could not hash to curve")]
    HashingError,

    #[error("could not deserialize: {0}")]
    DeserializationError(#[from] bincode::Error),
}

// A public trait cannot name a private one in its bounds (rust-lang/rust#34537),
// so the sealed trait lives in a public module inside a module that `sig`
// re-exports as `#[doc(hidden)]`. That is the sealing idiom, not a workaround
// awaiting a better one: the trait stays unimplementable from outside while the
// bound rustc names in a diagnostic remains a path the reader can import.
pub mod common {
    use super::*;

    /// BLSScheme is an internal trait that encompasses the common work between a
    /// BLS signature over G1 or G2.
    pub trait BLSScheme: Scheme {
        /// Returns sig = msg^{private}. The message MUST be hashed before this call.
        fn internal_sign(
            private: &Self::Private,
            msg: &[u8],
            should_hash: bool,
        ) -> Result<Vec<u8>, BLSError> {
            let mut h = if should_hash {
                let mut h = Self::Signature::zero();
                h.map(msg).map_err(|_| BLSError::HashingError)?;
                h
            } else {
                serialization::deserialize_from(msg)?
            };

            h.mul(private);

            let serialized = bincode::serialize(&h)?;
            Ok(serialized)
        }

        fn internal_verify(
            public: &Self::Public,
            msg: &[u8],
            sig_bytes: &[u8],
            should_hash: bool,
        ) -> Result<(), BLSError> {
            let sig: Self::Signature = serialization::deserialize_from(sig_bytes)?;

            let h = if should_hash {
                let mut h = Self::Signature::zero();
                h.map(msg).map_err(|_| BLSError::HashingError)?;
                h
            } else {
                serialization::deserialize_from(msg)?
            };

            Self::check_pairing(public, &sig, &h)
        }

        /// Rejects degenerate operands and then checks the pairing equation.
        ///
        /// An identity public key makes one side of `e(sig, g2) == e(hm, pub)`
        /// equal to 1 for every message, so it accepts the identity signature
        /// on anything. An identity message point does the same, and the blind
        /// scheme takes that point from the wire rather than from
        /// `hash_to_curve`, so it needs the same treatment. Rejecting the
        /// identity public key is the IETF BLS spec's `KeyValidate`.
        ///
        /// The signature itself is deliberately not checked: on its own it
        /// only fails the equation, and aggregation may legitimately produce
        /// it.
        fn check_pairing(
            public: &Self::Public,
            sig: &Self::Signature,
            hm: &Self::Signature,
        ) -> Result<(), BLSError> {
            if public == &Self::Public::zero() {
                return Err(BLSError::InvalidPublicKey);
            }

            if hm == &Self::Signature::zero() {
                return Err(BLSError::InvalidMessagePoint);
            }

            if !Self::final_exp(public, sig, hm) {
                return Err(BLSError::InvalidSig);
            }

            Ok(())
        }

        /// Performs the final exponentiation for the BLS sig scheme
        fn final_exp(p: &Self::Public, sig: &Self::Signature, hm: &Self::Signature) -> bool;
    }

    impl<T> SignatureScheme for T
    where
        T: BLSScheme,
    {
        type Error = BLSError;

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
        let left = C::pair(&C::G1::one(), sig);
        let right = C::pair(p, hm);
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
        let left = C::pair(sig, &Self::Public::one());
        let right = C::pair(hm, p);
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12377::{G1Curve, G2Curve, PairingCurve as PCurve};
    use crate::group::Curve;
    use rand::prelude::*;

    fn keypair<C: Curve>() -> (C::Scalar, C::Point) {
        let private = C::Scalar::rand(&mut thread_rng());
        let mut public = C::Point::one();
        public.mul(&private);
        (private, public)
    }

    #[test]
    fn nbls_g2() {
        let (private, public) = keypair::<G2Curve>();
        let msg = vec![1, 9, 6, 9];
        let sig = G2Scheme::<PCurve>::sign(&private, &msg).unwrap();
        G2Scheme::<PCurve>::verify(&public, &msg, &sig).expect("that should not happen");
    }

    #[test]
    fn nbls_g1() {
        let (private, public) = keypair::<G1Curve>();
        let msg = vec![1, 9, 6, 9];
        let sig = G1Scheme::<PCurve>::sign(&private, &msg).unwrap();
        G1Scheme::<PCurve>::verify(&public, &msg, &sig).expect("that should not happen");
    }

    /// The identity public key satisfies `e(sig, g2) == e(H(m), pub)` for every
    /// message, so an identity signature under it would otherwise verify
    /// anything. The encoding itself stays legal — only verification rejects it.
    fn identity_key_verifies_nothing<S>(pubkey_len: usize)
    where
        S: SignatureScheme<Error = BLSError>,
    {
        let identity_sig = bincode::serialize(&S::Signature::zero()).unwrap();

        let encoded = bincode::serialize(&S::Public::zero()).unwrap();
        assert_eq!(encoded.len(), pubkey_len);
        assert_eq!(
            encoded.last(),
            Some(&0x40),
            "the identity encodes as the point-at-infinity flag"
        );

        let identity: S::Public = serialization::deserialize(&encoded).unwrap();
        assert_eq!(
            identity,
            S::Public::zero(),
            "the identity must stay deserializable"
        );

        for msg in [&b"attack at dawn"[..], b"totally different", b""] {
            assert!(
                matches!(
                    S::verify(&identity, msg, &identity_sig),
                    Err(BLSError::InvalidPublicKey)
                ),
                "identity public key verified {msg:?}"
            );
        }
    }

    /// An identity signature is a bad signature rather than a rejected one: the
    /// IETF spec subgroup-checks signatures but never rejects the identity,
    /// since aggregation can legitimately produce it.
    fn identity_signature_is_merely_invalid<S>()
    where
        S: SignatureScheme<Error = BLSError>,
    {
        let (private, public) = S::keypair(&mut thread_rng());
        let msg = b"attack at dawn";

        let identity_sig = bincode::serialize(&S::Signature::zero()).unwrap();
        assert!(matches!(
            S::verify(&public, msg, &identity_sig),
            Err(BLSError::InvalidSig)
        ));

        let sig = S::sign(&private, msg).unwrap();
        assert!(matches!(
            S::verify(&S::Public::zero(), msg, &sig),
            Err(BLSError::InvalidPublicKey)
        ));
    }

    /// Pins the degeneracy the guard exists for: an identity public key, or an
    /// identity message point, satisfies the raw equation against an identity
    /// signature for any message. Were that to stop holding, the rejection
    /// tests above would keep passing while proving nothing.
    fn pairing_is_degenerate_on_identity<S>()
    where
        S: common::BLSScheme,
    {
        let mut hm = S::Signature::zero();
        hm.map(b"attack at dawn").expect("could not hash to curve");

        assert!(
            S::final_exp(&S::Public::zero(), &S::Signature::zero(), &hm),
            "identity public key should satisfy the raw pairing equation"
        );

        let (_, public) = S::keypair(&mut thread_rng());
        assert!(
            S::final_exp(&public, &S::Signature::zero(), &S::Signature::zero()),
            "identity message point should satisfy the raw pairing equation"
        );
    }

    #[test]
    fn identity_g1() {
        pairing_is_degenerate_on_identity::<G1Scheme<PCurve>>();
        identity_key_verifies_nothing::<G1Scheme<PCurve>>(48);
        identity_signature_is_merely_invalid::<G1Scheme<PCurve>>();
    }

    #[test]
    fn identity_g2() {
        pairing_is_degenerate_on_identity::<G2Scheme<PCurve>>();
        identity_key_verifies_nothing::<G2Scheme<PCurve>>(96);
        identity_signature_is_merely_invalid::<G2Scheme<PCurve>>();
    }
}
