use crate::group::{Element, Encodable, PairingCurve};
use crate::sig::{Scheme, SignatureScheme};
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;

// private module workaround to avoid leaking a private
// trait into a public trait
// see https://github.com/rust-lang/rust/issues/34537
// XXX another way to pull it off without this hack?
mod common {
    use super::*;
    // BLSScheme is an internal trait that encompasses the common work between a
    // BLS signature over G1 or G2.
    pub trait BLSScheme: Scheme {
        fn internal_sign(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            // sig = H(m)^x
            let mut h = Self::Signature::new();
            h.unmarshal(msg)?;
            //println!("sign: message {:?}", h);
            h.mul(private);
            Ok(h.marshal())
        }

        fn internal_verify(
            msg: &[u8],
            sig: &[u8],
        ) -> Result<(Self::Signature, Self::Signature), Box<dyn Error>> {
            let mut sigp = Self::Signature::new();
            if let Err(_) = sigp.unmarshal(sig) {
                return Err(Box::new(BLSError::InvalidPoint));
            }
            // H(m)
            let mut h = Self::Signature::new();
            h.unmarshal(msg)?;
            return Ok((sigp, h));
        }

        fn final_exp(p: &Self::Public, sig: &Self::Signature, hm: &Self::Signature) -> bool;
    }
    impl<T> SignatureScheme for T
    where
        T: BLSScheme,
    {
        fn sign(private: &Self::Private, msg: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            T::internal_sign(private, msg)
        }
        fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>> {
            match T::internal_verify(msg, sig) {
                Ok((sig, hm)) => {
                    if T::final_exp(public, &sig, &hm) {
                        Ok(())
                    } else {
                        Err(Box::new(BLSError::InvalidSig))
                    }
                }
                Err(e) => Err(e),
            }
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

/// BLSError are thrown out when using the BLS signature scheme.
#[derive(Debug)]
pub enum BLSError {
    /// InvalidPoint is raised when signature given to verification is not a
    /// valid point on the curve.
    InvalidPoint,
    /// InvalidSig is raised when the validation routine of the BLS algorithm
    /// does not finish successfully,i.e. it is an invalid signature.
    InvalidSig,
}

impl fmt::Display for BLSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use BLSError::*;
        match self {
            InvalidPoint => write!(f, "invalid point signature"),
            InvalidSig => write!(f, "invalid signature"),
        }
    }
}

impl Error for BLSError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        // TODO
        None
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
