use crate::poly::{Poly, Eval,PolyError};
use crate::sig::{BlindThresholdScheme, ThresholdScheme,BlindScheme, Partial};
use crate::sig::blind::BlindError;
use serde::{Deserialize, Serialize};
use crate::sig::tbls::Share;
use thiserror::Error;

#[derive(Debug, Error)]
// TODO: Can we get rid of this static lifetime bound?
/// Errors associated with partially unblinding a signature
pub enum BlindThresholdError<E: 'static + std::error::Error> {
    /// Raised when unblinding fails
    #[error(transparent)]
    BlindError(E),

    /// Raised when (de)serialization fails
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
}

impl<T> BlindThresholdScheme for T
where
    T: 'static + ThresholdScheme + BlindScheme,
{
    type Error = BlindThresholdError<<T as BlindScheme>::Error>;

    fn sign_blind_partial(private: &Share<Self::Private>, blinded_msg: &[u8]) -> Result<Partial, <Self as BlindThresholdScheme>::Error> {
        let sig = Self::blind_sign(&private.private,blinded_msg).map_err(BlindThresholdError::BlindError)?;
        let partial = Eval {
            value: sig,
            index: private.index,
        };
        bincode::serialize(&partial).map_err(BlindThresholdError::BincodeError)
    }

    fn unblind_partial_sig(
        t: &Self::Token,
        partial: &[u8],
    ) -> Result<Partial, <Self as BlindThresholdScheme>::Error> {
        // deserialize the sig
        let partial: Eval<Vec<u8>> = bincode::deserialize(partial)?;

        let partially_unblinded =
            Self::unblind_sig(t, &partial.value).map_err(BlindThresholdError::BlindError)?;
        let partially_unblinded = Eval {
            index: partial.index,
            value: partially_unblinded,
        };
        bincode::serialize(&partially_unblinded).map_err(BlindThresholdError::BincodeError)
    }

    fn verify_blind_partial(
        public: &Poly<Self::Public>,
        blind_msg: &[u8],
        blind_partial: &[u8],
    ) -> Result<(), <Self as BlindThresholdScheme>::Error> {
        let blinded_partial: Eval<Vec<u8>> = bincode::deserialize(blind_partial)?;
        let public_i = public.eval(blinded_partial.index);
        Self::blind_verify(&public_i.value,blind_msg,&blinded_partial.value).map_err(BlindThresholdError::BlindError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "bls12_381")]
    use crate::curve::bls12381::PairingCurve as PCurve;
    #[cfg(feature = "bls12_377")]
    use crate::curve::zexe::PairingCurve as Zexe;
    use crate::poly::{Idx, Poly};
    use crate::sig::{
        bls::{G1Scheme, G2Scheme},
        tbls::Share,
        SignatureScheme,
    };
    use rand::thread_rng;

    fn shares<B: BlindThresholdScheme>(
        n: usize,
        t: usize,
    ) -> (Vec<Share<B::Private>>, Poly<B::Public>) {
        let private = Poly::<B::Private>::new(t - 1);
        let shares = (0..n)
            .map(|i| private.eval(i as Idx))
            .map(|e| Share {
                index: e.index,
                private: e.value,
            })
            .collect();
        (shares, private.commit())
    }

    #[cfg(feature = "bls12_377")]
    #[test]
    fn tblind_g1_zexe_unblind() {
        aggregate_partially_unblinded::<G1Scheme<Zexe>>();
    }

    #[cfg(feature = "bls12_377")]
    #[test]
    fn tblind_g2_zexe_unblind() {
        aggregate_partially_unblinded::<G2Scheme<Zexe>>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn tblind_g1_bellman_unblind() {
        aggregate_partially_unblinded::<G1Scheme<PCurve>>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn tblind_g2_bellman_unblind() {
        aggregate_partially_unblinded::<G2Scheme<PCurve>>();
    }

    fn aggregate_partially_unblinded<B>()
    where
        B: BlindThresholdScheme + SignatureScheme + ThresholdScheme,
    {
        let n = 5;
        let thr = 4;
        let (shares, public) = shares::<B>(n, thr);
        let msg = vec![1, 9, 6, 9];

        // blind the msg
        let (token, blinded) = B::blind_msg(&msg, &mut thread_rng());

        // partially sign it
        let partials: Vec<_> = shares
            .iter()
            .map(|share| B::sign_blind_partial(share, &blinded).unwrap())
            .collect();

        // verify if each blind partial signatures is correct
        assert_eq!(false,partials
            .iter()
            .any(|p| B::verify_blind_partial(&public, &blinded,p).is_err()));


        // unblind each partial sig
        let unblindeds: Vec<_> = partials
            .iter()
            .map(|p| B::unblind_partial_sig(&token, p).unwrap())
            .collect();

        // aggregate
        let final_sig = B::aggregate(thr, &unblindeds).unwrap();

        B::verify(&public.public_key(), &msg, &final_sig).unwrap();
    }
}
