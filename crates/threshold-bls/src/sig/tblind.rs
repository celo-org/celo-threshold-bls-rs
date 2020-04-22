use crate::sig::tbls::{IndexSerializerError, Serializer};
use crate::sig::{BlindThreshold, Blinder, Partial, ThresholdScheme};

use thiserror::Error;

#[derive(Debug, Error)]
// TODO: Can we get rid of this static lifetime bound?
pub enum BlindThresholdError<E: 'static + std::error::Error> {
    #[error(transparent)]
    SerializerError(#[from] IndexSerializerError),
    #[error(transparent)]
    BlinderError(E),
}

impl<T> BlindThreshold for T
where
    T: 'static + ThresholdScheme + Blinder + Serializer,
{
    type Error = BlindThresholdError<<T as Blinder>::Error>;

    fn unblind_partial(
        t: &Self::Token,
        partial: &Partial,
    ) -> Result<Partial, <Self as BlindThreshold>::Error> {
        let (index, sig) = Self::extract(partial)?;
        let partially_unblinded =
            Self::unblind(t, &sig).map_err(BlindThresholdError::BlinderError)?;
        let injected = T::inject(index, &partially_unblinded);

        Ok(injected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "bls12_381")]
    use crate::curve::bls12381::PairingCurve as PCurve;
    #[cfg(feature = "bls12_377")]
    use crate::curve::zexe::PairingCurve as Zexe;
    use crate::sig::bls::{G1Scheme, G2Scheme};
    use crate::{poly::Poly, Share};
    use rand::thread_rng;

    use crate::{
        group::{Element, Encodable, Point},
        Index,
    };
    fn shares<B: BlindThreshold>(
        n: usize,
        t: usize,
    ) -> (Vec<Share<B::Private>>, Poly<B::Private, B::Public>) {
        let private = Poly::<B::Private, B::Private>::new(t - 1);
        let shares = (0..n)
            .map(|i| private.eval(i as Index))
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
        B: BlindThreshold,
    {
        let n = 5;
        let thr = 4;
        let (shares, public) = shares::<B>(n, thr);
        let msg = vec![1, 9, 6, 9];

        // blind the msg
        let (token, blinded) = B::blind(&msg, &mut thread_rng());

        // hash it
        let mut msg_point = B::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();

        // partially sign it
        let partials: Vec<_> = shares
            .iter()
            .map(|share| B::partial_sign(share, &blinded).unwrap())
            .collect();

        // unblind each partial sig
        let unblindeds: Vec<_> = partials
            .iter()
            .map(|p| {
                let ret = B::unblind_partial(&token, p).unwrap();
                ret
            })
            .collect();

        // aggregate
        let final_sig = B::aggregate(thr, &unblindeds).unwrap();

        B::verify(&public.public_key(), &msg_point_bytes, &final_sig).unwrap();
    }
}
