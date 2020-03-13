use crate::poly::Poly;
use crate::sig::blind::{BG1Scheme, BG2Scheme};
use crate::sig::tbls::{Serializer, TScheme};
use crate::sig::{
    BlindThreshold, Blinder, Partial, Scheme as SScheme, SignatureScheme, ThresholdScheme2,
};
use crate::{Index, Share};
use std::error::Error;
use std::marker::PhantomData;

pub struct Scheme<T: ThresholdScheme2 + Serializer, B: Blinder> {
    m: PhantomData<T>,
    b: PhantomData<B>,
}

type G1Scheme<C> = Scheme<TScheme<BG1Scheme<C>>, BG1Scheme<C>>;
type G2Scheme<C> = Scheme<TScheme<BG2Scheme<C>>, BG2Scheme<C>>;

impl<T, B> SScheme for Scheme<T, B>
where
    T: ThresholdScheme2 + Serializer,
    B: Blinder,
{
    type Private = T::Private;
    type Public = T::Public;
    type Signature = T::Signature;
}

impl<T, B> ThresholdScheme2 for Scheme<T, B>
where
    T: ThresholdScheme2 + Serializer,
    B: Blinder,
{
    fn partial_sign(private: &Share<T::Private>, msg: &[u8]) -> Result<Partial, Box<Error>> {
        T::partial_sign(private, msg)
    }
    fn partial_verify(
        public: &Poly<T::Private, T::Public>,
        msg: &[u8],
        partial: &Partial,
    ) -> Result<(), Box<Error>> {
        T::partial_verify(public, msg, partial)
    }
    // XXX Is thre a way to map Vec<Vec<u8>> to &[&[u8]] ?
    fn aggregate(
        public: &Poly<T::Private, T::Public>,
        msg: &[u8],
        partials: &[Partial],
    ) -> Result<Partial, Box<Error>> {
        T::aggregate(public, msg, partials)
    }
    fn verify(public: &T::Public, msg: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>> {
        T::verify(public, msg, sig)
    }
}
impl<T, B> Blinder for Scheme<T, B>
where
    T: ThresholdScheme2 + Serializer,
    B: Blinder,
{
    type Token = B::Token;
    fn blind(msg: &[u8]) -> (B::Token, Vec<u8>) {
        B::blind(msg)
    }
    fn unblind(t: B::Token, buff_blindp: &[u8]) -> Result<Vec<u8>, Box<Error>> {
        let (i, blind_partial) = T::extract(buff_blindp)?;
        let mut unblinded = B::unblind(t, &blind_partial)?;
        Ok(T::inject(i, &mut unblinded))
    }
}

impl<T, B> BlindThreshold for Scheme<T, B>
where
    T: ThresholdScheme2 + Serializer,
    B: Blinder,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12381::{PairingCurve as PCurve, Scalar, G1, G2};
    use crate::curve::zexe::PairingCurve as Zexe;
    use crate::sig::bls;
    use rand::prelude::*;

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

    #[test]
    fn tblind_g1_zexe() {
        tblind_test::<G1Scheme<Zexe>>();
    }

    #[test]
    fn tblind_g1() {
        tblind_test::<G1Scheme<PCurve>>();
    }

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
        let mut tokens_and_blinded: Vec<_> = shares.iter().map(|_| B::blind(&msg)).collect();
        let partials: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| B::partial_sign(share, &tokens_and_blinded[i].1).unwrap())
            .collect();

        let unblindeds: Vec<_> =
            tokens_and_blinded
                .into_iter()
                .enumerate()
                .fold(vec![], |mut acc, (i, (t, b))| {
                    match B::unblind(t, &partials[i]) {
                        Ok(unblinded) => {
                            println!("Unblinded {:?}", unblinded);
                            acc.push(unblinded);
                        }
                        Err(e) => {
                            panic!("error: {:?}", e);
                        }
                    };
                    acc
                });
        println!("unblindeds {:?}", unblindeds);
        unblindeds
            .iter()
            .for_each(|p| match B::partial_verify(&public, &msg, p) {
                Ok(()) => println!("all good"),
                Err(e) => panic!("e {:?}", e),
            });

        let final_sig = B::aggregate(&public, &msg, &unblindeds).unwrap();
        B::verify(&public.free_coeff(), &msg, &final_sig).unwrap();
    }
}
