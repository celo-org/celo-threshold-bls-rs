use crate::group::{Curve, Element, Encodable, G1Curve, G2Curve, PairingCurve, Point, Scalar};
use crate::poly::{Eval, Poly};
use crate::sig::bls;
use crate::sig::{Partial, Scheme as SScheme, SignatureScheme, ThresholdScheme2};
use crate::{Index, Public, Share};
use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;

pub trait Serializer {
    fn extract(partial: &[u8]) -> Result<(Index, Partial), TBLSError> {
        extract_index(partial)
    }
    fn inject(idx: Index, partial: &mut Partial) -> Vec<u8> {
        inject_index(idx, partial)
    }
}
impl<I> Serializer for TScheme<I> where I: SignatureScheme {}

pub struct TScheme<I: SignatureScheme> {
    i: PhantomData<I>,
}

impl<I> SScheme for TScheme<I>
where
    I: SignatureScheme,
{
    type Private = I::Private;
    type Public = I::Public;
    type Signature = I::Signature;
}

impl<I> ThresholdScheme2 for TScheme<I>
where
    I: SignatureScheme,
{
    fn partial_sign(private: &Share<Self::Private>, msg: &[u8]) -> Result<Vec<u8>, Box<Error>> {
        let mut sig = I::sign(&private.private, msg)?;
        let ret = inject_index(private.index, &mut sig);
        Ok(ret)
    }
    fn partial_verify(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partial: &Partial,
    ) -> Result<(), Box<Error>> {
        match extract_index(partial) {
            Ok((idx, bls_sig)) => {
                let public_i = public.eval(idx);
                I::verify(&public_i.value, msg, &bls_sig)
            }
            Err(e) => Err(Box::new(e)),
        }
    }
    fn aggregate(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partials: &[Partial],
    ) -> Result<Vec<u8>, Box<Error>> {
        let threshold = public.degree() + 1;
        if threshold > partials.len() {
            return Err(Box::new(TBLSError::NotEnoughPartialSignatures));
        }
        let valid_partials = partials
            .iter()
            .filter(|s| Self::partial_verify(public, msg, s).is_ok())
            .map(|s| extract_index(s))
            .filter_map(Result::ok)
            .map(|(idx, bls_sig)| {
                let mut p = Self::Signature::new();
                match p.unmarshal(&bls_sig) {
                    Ok(_) => Ok(Eval {
                        value: p,
                        index: idx,
                    }),
                    Err(e) => Err(e),
                }
            })
            .filter_map(Result::ok)
            .collect();
        let recovered_poly =
            Poly::<Self::Private, Self::Signature>::recover(threshold, valid_partials);
        // TODO avoid useless cloning here
        let recoverd_sig = recovered_poly.free_coeff();
        Ok(recoverd_sig.marshal())
    }

    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>> {
        I::verify(public, msg, sig)
    }
}

#[derive(Debug)]
pub enum TBLSError {
    BLSError,
    InvalidLength,
    NotEnoughPartialSignatures,
}

impl fmt::Display for TBLSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TBLSError::*;
        match self {
            InvalidLength => write!(f, "invalid length of signature"),
            NotEnoughPartialSignatures => write!(f, "not enough partial signatures"),
            BLSError => write!(f, "{}", self),
        }
    }
}

// This is important for other errors to wrap this one.
impl Error for TBLSError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        // TODO
        None
    }
}

fn inject_index(index: Index, sig: &mut Vec<u8>) -> Vec<u8> {
    let mut idx_slice = index.to_le_bytes().to_vec();
    let mut full_vector = Vec::with_capacity(idx_slice.len() + sig.len());
    full_vector.append(&mut idx_slice);
    full_vector.append(sig);
    return full_vector.to_vec();
}

fn extract_index(sig: &[u8]) -> Result<(Index, Vec<u8>), TBLSError> {
    let size_idx = std::mem::size_of::<Index>();
    if sig.len() < size_idx {
        return Err(TBLSError::InvalidLength);
    }
    let (int_bytes, rest) = sig.split_at(size_idx);
    let index = Index::from_le_bytes(int_bytes.try_into().unwrap());
    Ok((index, rest.to_vec()))
}

pub type TG1Scheme<C> = TScheme<bls::G1Scheme<C>>;
pub type TG2Scheme<C> = TScheme<bls::G2Scheme<C>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::{PairingCurve as PCurve, Scalar, G1, G2};
    use crate::poly::PrivatePoly;
    use rand::prelude::*;

    type G1C = G1Curve<PCurve>;

    type ShareCreator<T: ThresholdScheme2> =
        fn(usize, usize) -> (Vec<Share<T::Private>>, Poly<T::Private, T::Public>);

    fn shares<T: ThresholdScheme2>(
        n: usize,
        t: usize,
    ) -> (Vec<Share<T::Private>>, Poly<T::Private, T::Public>) {
        let private = Poly::<T::Private, T::Private>::new(t - 1);
        let shares = (0..n)
            .map(|i| private.eval(i as Index))
            .map(|e| Share {
                index: e.index,
                private: e.value,
            })
            .collect();
        (shares, private.commit())
    }

    // TODO make a macro

    #[test]
    fn inject() {
        let mut sig: Vec<u8> = (0..48).collect();
        let siglen = sig.len();
        let c = sig.clone();
        let extended = inject_index(4 as Index, &mut sig);
        let size_idx = std::mem::size_of::<Index>();
        assert_eq!(extended.len(), siglen + size_idx);
        assert_eq!(&extended[size_idx..], c.as_slice());
    }

    fn test_threshold_scheme<T: ThresholdScheme2>(creator: ShareCreator<T>) {
        let (shares, public) = creator(5, 4);
        let msg = vec![1, 9, 6, 9];
        let partials: Vec<_> = shares
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();
        assert_eq!(
            false,
            partials
                .iter()
                .any(|p| T::partial_verify(&public, &msg, &p).is_err())
        );
        let final_sig = T::aggregate(&public, &msg, &partials).unwrap();
        T::verify(&public.free_coeff(), &msg, &final_sig).unwrap();
    }

    #[test]
    fn threshold_g1() {
        test_threshold_scheme::<TG1Scheme<PCurve>>(shares::<TG1Scheme<PCurve>>);
    }

    #[test]
    fn threshold_g2() {
        test_threshold_scheme::<TG2Scheme<PCurve>>(shares::<TG2Scheme<PCurve>>);
    }
    /*}*/
}
