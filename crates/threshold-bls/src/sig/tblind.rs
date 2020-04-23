use crate::sig::tbls::{IndexSerializerError, Serializer};
use crate::sig::blind::BlindVerifier;
use crate::poly::Poly;
use crate::sig::{BlindThresholdScheme, Blinder, Partial, ThresholdScheme};

use thiserror::Error;

#[derive(Debug, Error)]
// TODO: Can we get rid of this static lifetime bound?
pub enum BlindThresholdError<E: 'static + std::error::Error> {
    #[error(transparent)]
    SerializerError(#[from] IndexSerializerError),
    #[error(transparent)]
    BlinderError(E),
}

impl<T> BlindThresholdScheme for T
where
    T: 'static + ThresholdScheme + Blinder + Serializer + BlindVerifier,
{
    type Error = BlindThresholdError<<T as Blinder>::Error>;

    fn unblind_partial(
        t: &Self::Token,
        partial: &Partial,
    ) -> Result<Partial, <Self as BlindThresholdScheme>::Error> {
        let (index, sig) = Self::extract(partial)?;
        let partially_unblinded =
            Self::unblind(t, &sig).map_err(BlindThresholdError::BlinderError)?;
        let injected = Self::inject(index, &partially_unblinded);

        Ok(injected)
    }
     fn partial_verify_blind( public: &Poly<Self::Private, Self::Public>,
        blinded_msg: &[u8],
        blinded_partial: &Partial,
    ) -> Result<(), String>{ 
        //let (index,blindsig) = T::extract(blinded_partial)?;
         match T::extract(blinded_partial) {
            Ok((index,blindsig)) => {
                let public_i = public.eval(index);
                T::private_blind_verify(&public_i.value, blinded_msg, &blindsig)
            },
            Err(e) => Err(String::from("Aie")),
         }
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
    fn shares<B: BlindThresholdScheme>(
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
        B: BlindThresholdScheme,
    {
        let n = 5;
        let thr = 4;
        let (shares, public) = shares::<B>(n, thr);
        let msg = vec![1, 9, 6, 9];

        // blind the msg
        let (token, blinded) = B::blind(&msg, &mut thread_rng());

        // partially sign it
        let partials: Vec<_> = shares
            .iter()
            // Issue is here - it should not use the same "partial_sign" as tbls
            // provides, it should override it to use a combination of
            // BlindScheme and ThresholdScheme 
            // 1. BlindScheme::sign_blind
            // 2. Inject index to the result
            .map(|share| B::partial_sign(share, &blinded).unwrap())
            .collect();

        // check they are all correct
        /*assert_eq!(false,*/
            //partials.iter()
            /*.any(|p| B::partial_verify_blind(&public,&blinded,p).is_err()));*/
        /*partials.iter().for_each(|p| {*/
            //match B::partial_verify_blind(&public,&blinded,p) {
                //Ok(()) => println!("winner"),
                //Err(e) => println!("{:?}",e),
            //}
        //});

        // unblind each partial sig
        // the unblinding can be done before on each partials or after on the
        // final signature
        let unblindeds: Vec<_> = partials
            .iter()
            .map(|p| {
                let ret = B::unblind_partial(&token, p).unwrap();
                ret
            })
            .collect();

        // aggregate
        let final_sig = B::aggregate(thr, &unblindeds).unwrap();

        B::verify(&public.public_key(), &msg, &final_sig).unwrap();
    }
}
