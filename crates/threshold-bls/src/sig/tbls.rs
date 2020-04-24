//! Implements Threshold Signatures for all Signature Scheme implementers
use crate::group::{Element, Encodable};
use crate::poly::{Eval, Poly, PolyError};
use crate::sig::{
    Partial, SignatureScheme, SignatureSchemeExt, ThresholdScheme, ThresholdSchemeExt,
};
use crate::{Index, Share};
use std::{convert::TryInto, fmt::Debug};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IndexSerializerError {
    #[error("signature did not contain an index, need at least {1} bytes, got {0}")]
    InvalidLength(usize, usize),
    #[error("could not deserialize index: {0}")]
    IndexError(#[from] std::array::TryFromSliceError),
}

#[derive(Debug, Error)]
pub enum ThresholdError<I: SignatureScheme> {
    #[error("could not recover public key: {0}")]
    PolyError(PolyError<I::Signature>),

    #[error(transparent)]
    IndexError(#[from] IndexSerializerError),

    #[error("signing error {0}")]
    SignatureError(I::Error),

    #[error("not enough partial signatures: {0}/{1}")]
    NotEnoughPartialSignatures(usize, usize),
}

/// Helper trait for serializing/deserializing indexes in a signature
pub trait Serializer {
    fn extract(partial: &[u8]) -> Result<(Index, Partial), IndexSerializerError> {
        extract_index(partial)
    }

    fn inject(idx: Index, partial: &[u8]) -> Vec<u8> {
        inject_index(idx, partial)
    }
}

impl<I: SignatureScheme> Serializer for I {}

impl<I: SignatureScheme> ThresholdScheme for I {
    type Error = ThresholdError<I>;

    fn partial_sign(
        private: &Share<Self::Private>,
        msg: &[u8],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        let mut sig = Self::sign(&private.private, msg).map_err(ThresholdError::SignatureError)?;
        let ret = inject_index(private.index, &mut sig);
        Ok(ret)
    }

    fn partial_verify(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partial: &[u8],
    ) -> Result<(), <Self as ThresholdScheme>::Error> {
        let (idx, bls_sig) = extract_index(partial)?;
        let public_i = public.eval(idx);
        Self::verify(&public_i.value, msg, &bls_sig).map_err(ThresholdError::SignatureError)
    }

    fn aggregate(
        threshold: usize,
        partials: &[Partial],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        if threshold > partials.len() {
            return Err(ThresholdError::NotEnoughPartialSignatures(
                partials.len(),
                threshold,
            ));
        }

        let valid_partials: Vec<Eval<Self::Signature>> = partials
            .iter()
            .map(|s| extract_index(s))
            .filter_map(Result::ok)
            .map(|(idx, bls_sig)| {
                let mut p = Self::Signature::one();
                match p.unmarshal(&bls_sig) {
                    Ok(_) => Ok(Eval {
                        value: p,
                        index: idx,
                    }),
                    Err(e) => {
                        println!("error unmarshalling signature when aggregating: buff {:?} \n\t err ->  {:?}", bls_sig.len() ,e);
                        Err(e)
                    }
                }
            })
            .filter_map(Result::ok)
            .collect();

        let recovered_sig =
            Poly::<Self::Private, Self::Signature>::recover(threshold, valid_partials)
                .map_err(ThresholdError::PolyError)?;
        Ok(recovered_sig.marshal())
    }

    fn verify(public: &Self::Public, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error> {
        <Self as SignatureScheme>::verify(public, msg, sig).map_err(ThresholdError::SignatureError)
    }
}

impl<I: SignatureSchemeExt> ThresholdSchemeExt for I {
    fn partial_sign_without_hashing(
        private: &Share<Self::Private>,
        msg: &[u8],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        let mut sig = Self::sign_without_hashing(&private.private, msg)
            .map_err(ThresholdError::SignatureError)?;
        let ret = inject_index(private.index, &mut sig);
        Ok(ret)
    }

    fn partial_verify_without_hashing(
        public: &Poly<Self::Private, Self::Public>,
        msg: &[u8],
        partial: &[u8],
    ) -> Result<(), <Self as ThresholdScheme>::Error> {
        let (idx, bls_sig) = extract_index(partial)?;
        let public_i = public.eval(idx);
        Self::verify_without_hashing(&public_i.value, msg, &bls_sig)
            .map_err(ThresholdError::SignatureError)
    }
}

fn inject_index(index: Index, sig: &[u8]) -> Vec<u8> {
    let mut res = index.to_le_bytes().to_vec();
    res.extend_from_slice(sig);
    res
}

fn extract_index(sig: &[u8]) -> Result<(Index, Vec<u8>), IndexSerializerError> {
    let size_idx = std::mem::size_of::<Index>();
    if sig.len() < size_idx {
        return Err(IndexSerializerError::InvalidLength(sig.len(), size_idx));
    }

    let (int_bytes, rest) = sig.split_at(size_idx);
    let index = Index::from_le_bytes(int_bytes.try_into()?);
    Ok((index, rest.to_vec()))
}

#[cfg(feature = "bls12_381")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::PairingCurve as PCurve;
    use crate::sig::{
        bls::{G1Scheme, G2Scheme},
        Scheme,
    };

    type ShareCreator<T> = fn(
        usize,
        usize,
    ) -> (
        Vec<Share<<T as Scheme>::Private>>,
        Poly<<T as Scheme>::Private, <T as Scheme>::Public>,
    );

    fn shares<T: ThresholdScheme>(
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
        let sig: Vec<u8> = (0..48).collect();
        let siglen = sig.len();
        let c = sig.clone();
        let extended = inject_index(4 as Index, &sig);
        let size_idx = std::mem::size_of::<Index>();
        assert_eq!(extended.len(), siglen + size_idx);
        assert_eq!(&extended[size_idx..], c.as_slice());
    }

    fn test_threshold_scheme<T: ThresholdScheme>(creator: ShareCreator<T>) {
        let threshold = 4;
        let (shares, public) = creator(5, threshold);
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
        let final_sig = T::aggregate(threshold, &partials).unwrap();

        T::verify(&public.free_coeff(), &msg, &final_sig).unwrap();
    }

    #[test]
    fn threshold_g1() {
        type S = G1Scheme<PCurve>;
        test_threshold_scheme::<S>(shares::<S>);
    }

    #[test]
    fn threshold_g2() {
        type S = G2Scheme<PCurve>;
        test_threshold_scheme::<S>(shares::<S>);
    }
}
