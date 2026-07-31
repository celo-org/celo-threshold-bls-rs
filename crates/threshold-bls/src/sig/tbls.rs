//! Threshold Signatures implementation for any type which implements
//! [`SignatureScheme`](../trait.SignatureScheme.html)
use crate::poly::{Eval, Idx, Poly, PolyError};
use crate::serialization;
use crate::sig::{Partial, SignatureScheme, ThresholdScheme};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

    /// ZeroThreshold is raised if aggregation is attempted with a threshold of
    /// zero, which would produce a signature from no partials at all
    #[error("threshold must be at least one")]
    ZeroThreshold,
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
        let partial: Eval<Vec<u8>> = serialization::deserialize(partial)?;

        let public_i = public.eval(partial.index);

        Self::verify(&public_i.value, msg, &partial.value).map_err(ThresholdError::SignatureError)
    }

    fn aggregate(
        threshold: usize,
        partials: &[Partial],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        if threshold == 0 {
            return Err(ThresholdError::ZeroThreshold);
        }

        if threshold > partials.len() {
            return Err(ThresholdError::NotEnoughPartialSignatures(
                partials.len(),
                threshold,
            ));
        }

        let valid_partials: Vec<Eval<Self::Signature>> = partials
            .iter()
            .map(|partial| {
                let eval: Eval<Vec<u8>> = serialization::deserialize(partial)?;
                let sig = serialization::deserialize(&eval.value)?;
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
        group::Element,
        sig::{
            bls::{BLSError, G1Scheme, G2Scheme},
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

    #[test]
    fn aggregate_rejects_a_zero_threshold_g1() {
        aggregate_rejects_a_zero_threshold::<G1Scheme<PCurve>>();
    }

    #[test]
    fn aggregate_rejects_a_zero_threshold_g2() {
        aggregate_rejects_a_zero_threshold::<G2Scheme<PCurve>>();
    }

    /// A threshold of zero used to pass both length guards and produce the
    /// identity signature from an empty slice — a valid-looking signature
    /// from no inputs at all.
    fn aggregate_rejects_a_zero_threshold<T>()
    where
        T: ThresholdScheme<Error = ThresholdError<T>> + SignatureScheme,
    {
        assert!(matches!(
            T::aggregate(0, &[]),
            Err(ThresholdError::ZeroThreshold)
        ));
    }

    #[test]
    fn aggregate_ignores_duplicate_partials_g1() {
        aggregate_ignores_duplicate_partials::<G1Scheme<PCurve>>();
    }

    #[test]
    fn aggregate_ignores_duplicate_partials_g2() {
        aggregate_ignores_duplicate_partials::<G2Scheme<PCurve>>();
    }

    /// A partial submitted twice (e.g. by a retrying signer) is one evaluation
    /// point, not two: aggregation succeeds as long as enough distinct
    /// partials remain.
    fn aggregate_ignores_duplicate_partials<T: ThresholdScheme + SignatureScheme>() {
        let threshold = 4;
        let (shares, public) = shares::<T>(5, threshold);
        let msg = vec![1, 9, 6, 9];

        let mut partials: Vec<_> = shares
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();
        partials.insert(0, partials[0].clone());
        partials.truncate(5);

        let final_sig = T::aggregate(threshold, &partials).unwrap();
        T::verify(public.public_key(), &msg, &final_sig).unwrap();
    }

    #[test]
    fn aggregate_rejects_duplicates_masking_a_shortfall_g1() {
        aggregate_rejects_duplicates_masking_a_shortfall::<G1Scheme<PCurve>>();
    }

    #[test]
    fn aggregate_rejects_duplicates_masking_a_shortfall_g2() {
        aggregate_rejects_duplicates_masking_a_shortfall::<G2Scheme<PCurve>>();
    }

    /// Duplicated partials must not count towards the threshold: fewer than
    /// threshold distinct evaluation points cannot recover the signature, and
    /// interpolating over them anyway would return a wrong one.
    fn aggregate_rejects_duplicates_masking_a_shortfall<T>()
    where
        T: ThresholdScheme<Error = ThresholdError<T>> + SignatureScheme,
    {
        let threshold = 4;
        let (shares, _) = shares::<T>(5, threshold);
        let msg = vec![1, 9, 6, 9];

        let mut partials: Vec<_> = shares[..threshold - 1]
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();
        partials.insert(0, partials[0].clone());

        assert!(matches!(
            T::aggregate(threshold, &partials),
            Err(ThresholdError::PolyError(PolyError::InvalidRecovery(3, 4)))
        ));
    }

    #[test]
    fn empty_polynomial_verifies_nothing_g1() {
        empty_polynomial_verifies_nothing::<G1Scheme<PCurve>>();
    }

    #[test]
    fn empty_polynomial_verifies_nothing_g2() {
        empty_polynomial_verifies_nothing::<G2Scheme<PCurve>>();
    }

    /// A public polynomial with no coefficients is a bare length prefix on the
    /// wire, and evaluates to the identity at every index. Rejecting the
    /// identity public key is what stops it standing in for a real key.
    fn empty_polynomial_verifies_nothing<T>()
    where
        T: SignatureScheme<Error = BLSError> + ThresholdScheme<Error = ThresholdError<T>>,
    {
        let empty: Poly<T::Public> = serialization::deserialize(&[0u8; 8]).unwrap();

        let partial = bincode::serialize(&Eval {
            index: 7,
            value: bincode::serialize(&<T as Scheme>::Signature::new()).unwrap(),
        })
        .unwrap();

        assert!(matches!(
            T::partial_verify(&empty, b"any message at all", &partial),
            Err(ThresholdError::SignatureError(BLSError::InvalidPublicKey))
        ));
    }
}
