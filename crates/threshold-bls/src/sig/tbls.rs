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
    /// Identifies the share's holder. It is not the x-coordinate the polynomial
    /// is evaluated at: that is `index + 1`, since evaluating at zero would hand
    /// out the secret itself.
    pub index: Idx,
    /// The scalar corresponding to the share's secret
    pub private: S,
}

/// Errors associated with threshold signing, verification and aggregation.
#[derive(Debug, Error)]
pub enum ThresholdError<I: SignatureScheme> {
    /// PolyError is raised when the public key could not be recovered
    #[error("could not recover public key: {0}")]
    PolyError(#[from] PolyError),

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
        let partial: Eval<Vec<u8>> = serialization::deserialize(partial)?;

        let public_i = public.eval(partial.index);

        Self::verify(&public_i.value, msg, &partial.value).map_err(ThresholdError::SignatureError)
    }

    fn aggregate(
        public: &Poly<Self::Public>,
        partials: &[Partial],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        // The polynomial always has at least one coefficient, so this is at
        // least 1 and the zero-threshold case cannot arise from here.
        let threshold = public.degree() + 1;

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

        let recovered_sig = Poly::<Self::Signature>::recover(threshold, valid_partials)?;
        Ok(bincode::serialize(&recovered_sig).expect("could not serialize"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::bls12377::PairingCurve as PCurve,
        sig::{
            Scheme, SignatureScheme,
            bls::{BLSError, G1Scheme, G2Scheme},
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

        assert!(
            !partials
                .iter()
                .any(|p| T::partial_verify(&public, &msg, p).is_err())
        );
        let final_sig = T::aggregate(&public, &partials).unwrap();

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
    fn aggregate_is_subset_independent_g1() {
        aggregate_is_subset_independent::<G1Scheme<PCurve>>();
    }

    #[test]
    fn aggregate_is_subset_independent_g2() {
        aggregate_is_subset_independent::<G2Scheme<PCurve>>();
    }

    /// Any t distinct partials determine the same degree t-1 polynomial, so
    /// the aggregated signature must be byte-identical no matter which valid
    /// subset the caller provides. A wrong Lagrange node or a bug in the
    /// subset selection would produce diverging signatures here.
    fn aggregate_is_subset_independent<T: ThresholdScheme + SignatureScheme>() {
        let threshold = 3;
        let (shares, public) = shares::<T>(5, threshold);
        let msg = vec![1, 9, 6, 9];

        let partials: Vec<_> = shares
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();

        let from_low_indices = T::aggregate(&public, &partials[0..3]).unwrap();
        let from_high_indices = T::aggregate(&public, &partials[2..5]).unwrap();

        assert_eq!(
            from_low_indices, from_high_indices,
            "different share subsets aggregated to different signatures"
        );
        T::verify(public.public_key(), &msg, &from_low_indices).unwrap();
    }

    #[test]
    fn aggregate_rejects_too_few_partials_g1() {
        aggregate_rejects_too_few_partials::<G1Scheme<PCurve>>();
    }

    #[test]
    fn aggregate_rejects_too_few_partials_g2() {
        aggregate_rejects_too_few_partials::<G2Scheme<PCurve>>();
    }

    /// Fewer partials than the polynomial's degree + 1 interpolate to a
    /// different polynomial, whose constant term is a valid-looking signature
    /// nobody produced. Nothing about the partials reveals that, so the count is
    /// checked against the polynomial the caller supplies — while the threshold
    /// was the caller's to state, too small a value returned that wrong
    /// signature with no error at all.
    fn aggregate_rejects_too_few_partials<T>()
    where
        T: ThresholdScheme<Error = ThresholdError<T>> + SignatureScheme,
    {
        let threshold = 4;
        let (shares, public) = shares::<T>(5, threshold);
        let msg = vec![1, 9, 6, 9];

        let partials: Vec<_> = shares
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();

        assert!(T::aggregate(&public, &partials[..threshold]).is_ok());
        assert!(matches!(
            T::aggregate(&public, &partials[..threshold - 1]),
            Err(ThresholdError::NotEnoughPartialSignatures(3, 4))
        ));
        assert!(matches!(
            T::aggregate(&public, &[]),
            Err(ThresholdError::NotEnoughPartialSignatures(0, 4))
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

        let final_sig = T::aggregate(&public, &partials).unwrap();
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
        let (shares, public) = shares::<T>(5, threshold);
        let msg = vec![1, 9, 6, 9];

        let mut partials: Vec<_> = shares[..threshold - 1]
            .iter()
            .map(|s| T::partial_sign(s, &msg).unwrap())
            .collect();
        partials.insert(0, partials[0].clone());

        assert!(matches!(
            T::aggregate(&public, &partials),
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

    /// A polynomial with no coefficients is a bare length prefix on the wire.
    /// It used to parse and evaluate to the identity at every index, leaving
    /// the identity public key check to stop it. That check still exists; this
    /// asserts the input no longer reaches it.
    fn empty_polynomial_verifies_nothing<T>()
    where
        T: SignatureScheme<Error = BLSError> + ThresholdScheme<Error = ThresholdError<T>>,
    {
        let empty = serialization::deserialize::<Poly<T::Public>>(&[0u8; 8]);
        assert!(empty.is_err(), "a polynomial with no coefficients parsed");
    }
}
