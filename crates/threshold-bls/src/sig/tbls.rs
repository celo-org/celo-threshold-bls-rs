//! Threshold Signatures implementation for any type which implements
//! [`SignatureScheme`](../trait.SignatureScheme.html)
use crate::poly::{Eval, Idx, Poly, PolyError};
use crate::sig::{Partial, SignatureScheme, ThresholdScheme};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// A private share which is part of the threshold signing key
pub struct Share<S> {
    /// The share's index in the polynomial
    pub index: Idx,
    /// The scalar corresponding to the share's secret
    pub private: S,
}

/// Errors associated with threshold signing, verification and aggregation.
#[derive(Debug, Error)]
pub enum ThresholdError<I: SignatureScheme> {
    /// PolyError is raised when the public key could not be recovered
    #[error("could not recover public key: {0}")]
    PolyError(PolyError),

    /// BincodeError is raised when there is an error in (de)serialization
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),

    /// SignatureError is raised when there is an error in threshold signing
    #[error("signing error {0}")]
    SignatureError(I::Error),

    /// NotEnoughPartialSignatures is raised if the signatures provided for aggregation
    /// were fewer than the threshold
    #[error("not enough partial signatures: {0}/{1}")]
    NotEnoughPartialSignatures(usize, usize),
}

impl<I: SignatureScheme> ThresholdScheme for I {
    type Error = ThresholdError<I>;

    fn partial_sign(
        private: &Share<Self::Private>,
        msg: &[u8],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        let sig = Self::sign(&private.private, msg).map_err(ThresholdError::SignatureError)?;
        let partial = Eval {
            value: sig,
            index: private.index,
        };
        let ret = bincode::serialize(&partial)?;
        Ok(ret)
    }

    fn partial_verify(
        public: &Poly<Self::Public>,
        msg: &[u8],
        partial: &[u8],
    ) -> Result<(), <Self as ThresholdScheme>::Error> {
        let partial: Eval<Vec<u8>> = bincode::deserialize(partial)?;

        let public_i = public.eval(partial.index);

        Self::verify(&public_i.value, msg, &partial.value).map_err(ThresholdError::SignatureError)
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
            .map(|partial| {
                let eval: Eval<Vec<u8>> = bincode::deserialize(partial)?;
                let sig = bincode::deserialize(&eval.value)?;
                Ok(Eval {
                    index: eval.index,
                    value: sig,
                })
            })
            .collect::<Result<_, <Self as ThresholdScheme>::Error>>()?;

        let recovered_sig = Poly::<Self::Signature>::recover(threshold, valid_partials)
            .map_err(ThresholdError::PolyError)?;
        Ok(bincode::serialize(&recovered_sig).expect("could not serialize"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::bls12377::PairingCurve as PCurve,
        sig::{
            bls::{G1Scheme, G2Scheme},
            Scheme, SignatureScheme,
        },
    };

    type ShareCreator<T> = fn(
        usize,
        usize,
    ) -> (
        Vec<Share<<T as Scheme>::Private>>,
        Poly<<T as Scheme>::Public>,
    );

    fn shares<T: ThresholdScheme>(n: usize, t: usize) -> (Vec<Share<T::Private>>, Poly<T::Public>) {
        let private = Poly::<T::Private>::new(t - 1);
        let shares = (0..n)
            .map(|i| private.eval(i as Idx))
            .map(|e| Share {
                index: e.index,
                private: e.value,
            })
            .collect();
        (shares, private.commit())
    }

    fn test_threshold_scheme<T: ThresholdScheme + SignatureScheme>(creator: ShareCreator<T>) {
        let threshold = 4;
        let (shares, public) = creator(5, threshold);
        let msg = vec![1, 9, 6, 9];

        let partials: Vec<_> = shares
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();

        assert!(!partials
            .iter()
            .any(|p| T::partial_verify(&public, &msg, p).is_err()));
        let final_sig = T::aggregate(threshold, &partials).unwrap();

        T::verify(public.public_key(), &msg, &final_sig).unwrap();
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
