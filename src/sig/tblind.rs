use crate::poly::Poly;
use crate::sig::blind::{BG1Scheme, BG2Scheme};
use crate::sig::tbls::{Serializer, TScheme};
use crate::sig::{BlindThreshold, Blinder, Partial, Scheme as SScheme, ThresholdScheme};
use crate::Share;
use std::error::Error;
use std::marker::PhantomData;

pub struct Scheme<T: ThresholdScheme + Serializer, B: Blinder> {
    m: PhantomData<T>,
    b: PhantomData<B>,
}

pub type G1Scheme<C> = Scheme<TScheme<BG1Scheme<C>>, BG1Scheme<C>>;
pub type G2Scheme<C> = Scheme<TScheme<BG2Scheme<C>>, BG2Scheme<C>>;

impl<T, B> SScheme for Scheme<T, B>
where
    T: ThresholdScheme + Serializer,
    B: Blinder,
{
    type Private = T::Private;
    type Public = T::Public;
    type Signature = T::Signature;
}

impl<T, B> ThresholdScheme for Scheme<T, B>
where
    T: ThresholdScheme + Serializer,
    B: Blinder,
{
    fn partial_sign(private: &Share<T::Private>, msg: &[u8]) -> Result<Partial, Box<dyn Error>> {
        T::partial_sign(private, msg)
    }

    /// partial verify takes a blinded partial signature.
    fn partial_verify(
        public: &Poly<T::Private, T::Public>,
        msg: &[u8],
        partial: &Partial,
    ) -> Result<(), Box<dyn Error>> {
        T::partial_verify(public, msg, partial)
    }

    fn aggregate(threshold: usize, partials: &[Partial]) -> Result<Partial, Box<dyn Error>> {
        T::aggregate(threshold, partials)
    }

    fn verify(public: &T::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>> {
        T::verify(public, msg, sig)
    }
}
impl<T, B> Blinder for Scheme<T, B>
where
    T: ThresholdScheme + Serializer,
    B: Blinder,
{
    type Token = B::Token;
    fn blind(msg: &[u8]) -> (B::Token, Vec<u8>) {
        B::blind(msg)
    }
    fn unblind(t: &B::Token, blind_sig: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        B::unblind(&t, &blind_sig)
    }
}

impl<T, B> BlindThreshold for Scheme<T, B>
where
    T: ThresholdScheme + Serializer,
    B: Blinder,
{
    fn unblind_partial(t: &Self::Token, partial: &Partial) -> Result<Partial, Box<dyn Error>> {
        let (index, sig) = T::extract(partial)?;
        match B::unblind(t, &sig) {
            Ok(mut p) => Ok(T::inject(index, &mut p)),
            Err(e) => Err(e),
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

    use crate::{Index, group::{Element, Encodable, Point}};
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
    fn tblind_g1_zexe() {
        tblind_test::<G1Scheme<Zexe>>();
    }

    #[cfg(feature = "bls12_377")]
    #[test]
    fn tblind_g1_zexe_unblind() {
        unblind_then_aggregate_test::<G1Scheme<Zexe>>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn tblind_g1() {
        tblind_test::<G1Scheme<PCurve>>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn tblind_g2() {
        tblind_test::<G2Scheme<PCurve>>();
    }

    fn tblind_test<B>()
    where
        B: BlindThreshold,
    {
        let n = 5;
        let thr = 4;
        let (shares, public) = shares::<B>(n, thr);
        let msg = vec![1, 9, 6, 9];
        let mut msg_point = B::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();
        let (token, blinded) = B::blind(&msg);
        let partials: Vec<_> = shares
            .iter()
            .map(|share| B::partial_sign(share, &blinded).unwrap())
            .collect();
        assert_eq!(
            false,
            partials
                .iter()
                .any(|p| B::partial_verify(&public, &blinded, &p).is_err())
        );

        let blinded_sig = B::aggregate(thr, &partials).unwrap();
        let unblinded = B::unblind(&token, &blinded_sig).unwrap();

        B::verify(&public.public_key(), &msg_point_bytes, &unblinded).unwrap();
    }
    fn unblind_then_aggregate_test<B>()
    where
        B: BlindThreshold,
    {
        let n = 5;
        let thr = 4;
        let (shares, public) = shares::<B>(n, thr);
        let msg = vec![1, 9, 6, 9];
        let (token, blinded) = B::blind(&msg);
        let mut msg_point = B::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg_point_bytes = msg_point.marshal();
        let partials: Vec<_> = shares
            .iter()
            .map(|share| B::partial_sign(share, &blinded).unwrap())
            .collect();
        let unblindeds: Vec<_> = partials
            .iter()
            .map(|p| B::unblind_partial(&token, p))
            .filter_map(Result::ok)
            .collect();
        let final_sig = B::aggregate(thr, &unblindeds).unwrap();

        B::verify(&public.public_key(), &msg_point_bytes, &final_sig).unwrap();
    }
}
