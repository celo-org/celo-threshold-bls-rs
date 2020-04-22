use crate::group::{
    Curve as C, CurveFrom as CF, Element, Encodable, PairingCurve as PC, Point, Scalar as Sc,
};
use ff::{Field, PrimeField, PrimeFieldRepr};
use groupy::{CurveAffine, CurveProjective, EncodedPoint};
use paired::bls12_381::{
    Bls12, Fq12, Fr, FrRepr, G1Compressed, G2Compressed, G1 as PG1, G2 as PG2,
};
use paired::Engine;
use rand_core::RngCore;
use std::result::Result;

pub type Scalar = Fr;
pub type G1 = PG1;
pub type G2 = PG2;
pub type GT = Fq12;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BellmanError {
    #[error("decoding: invalid length {0}/{1}")]
    InvalidLength(usize, usize),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Field Decoding Error: {0}")]
    PrimeFieldDecodingError(#[from] ff::PrimeFieldDecodingError),
    #[error("Group Decoding Error: {0}")]
    GroupDecodingError(#[from] groupy::GroupDecodingError),
}

impl Element<Scalar> for Scalar {
    fn new() -> Self {
        ff::Field::zero()
    }

    fn one() -> Self {
        ff::Field::one()
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &Fr) {
        self.mul_assign(mul)
    }
    fn pick<R: RngCore>(&mut self, rng: &mut R) {
        *self = Fr::random(rng)
    }
}

impl Encodable for Scalar {
    type Error = BellmanError;

    fn marshal_len() -> usize {
        32
    }

    fn marshal(&self) -> Vec<u8> {
        let repr = self.into_repr();
        let mut out = Vec::with_capacity((repr.num_bits() / 8) as usize);
        repr.write_le(&mut out)
            .expect("writing to buff should not fail");
        out
    }

    fn unmarshal(&mut self, data: &[u8]) -> Result<(), BellmanError> {
        if data.len() != 32 {
            return Err(BellmanError::InvalidLength(data.len(), 32));
        }
        let mut out = FrRepr::default();
        out.read_le(data)?;
        *self = Fr::from_repr(out)?.into();
        Ok(())
    }
}

/// Implementation of Scalar using field elements used in BLS12-381
impl Sc for Scalar {
    fn set_int(&mut self, i: u64) {
        *self = Fr::from_repr(FrRepr::from(i)).unwrap();
    }

    fn inverse(&self) -> Option<Self> {
        ff::Field::inverse(self)
    }

    fn negate(&mut self) {
        ff::Field::negate(self);
    }

    fn sub(&mut self, other: &Self) {
        self.sub_assign(other);
    }
}
/// G1 points can be multiplied by Fr elements
impl Element<Scalar> for G1 {
    fn new() -> Self {
        groupy::CurveProjective::zero()
    }

    fn one() -> Self {
        groupy::CurveProjective::one()
    }

    fn pick<R: RngCore>(&mut self, mut rng: &mut R) {
        *self = G1::random(&mut rng)
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.mul_assign(FrRepr::from(*mul))
    }
}

impl Encodable for G1 {
    type Error = BellmanError;

    fn marshal_len() -> usize {
        48
    }
    fn marshal(&self) -> Vec<u8> {
        let c = self.into_affine().into_compressed();
        let out = c.as_ref().clone();
        out.to_vec()
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), BellmanError> {
        if data.len() != Self::marshal_len() {
            return Err(BellmanError::InvalidLength(data.len(), Self::marshal_len()));
        }
        let mut c = G1Compressed::empty();
        c.as_mut().copy_from_slice(data);

        // Is there a better way to go from G1Compressed to G1?
        let affine = c.into_affine()?;
        *self = affine.into_projective();

        Ok(())
    }
}

impl Encodable for G2 {
    type Error = BellmanError;

    fn marshal_len() -> usize {
        96
    }

    fn marshal(&self) -> Vec<u8> {
        let c = self.into_affine().into_compressed();
        let out = c.as_ref().clone();
        out.to_vec()
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), BellmanError> {
        if data.len() != Self::marshal_len() {
            return Err(BellmanError::InvalidLength(data.len(), Self::marshal_len()));
        }

        let mut c = G2Compressed::empty();
        // TODO this can panic ! (when?)
        c.as_mut().copy_from_slice(data);
        let affine = c.into_affine()?;
        *self = affine.into_projective();

        Ok(())
    }
}

impl Element<Scalar> for G2 {
    fn new() -> Self {
        groupy::CurveProjective::zero()
    }

    fn one() -> Self {
        groupy::CurveProjective::one()
    }

    fn pick<R: RngCore>(&mut self, mut rng: &mut R) {
        *self = G2::random(&mut rng)
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.mul_assign(FrRepr::from(*mul))
    }
}

/// Implementation of Point using G1 from BLS12-381
impl Point<Fr> for G1 {
    type Error = ();

    fn map(&mut self, data: &[u8]) -> Result<(), ()> {
        *self = G1::hash(data);
        Ok(())
    }
}

/// Implementation of Point using G2 from BLS12-381
impl Point<Fr> for G2 {
    type Error = ();

    fn map(&mut self, data: &[u8]) -> Result<(), ()> {
        *self = G2::hash(data);
        Ok(())
    }
}

impl Element for GT {
    fn new() -> Self {
        ff::Field::zero()
    }

    fn one() -> Self {
        ff::Field::one()
    }
    fn add(&mut self, s2: &Self) {
        self.add_assign(s2);
    }
    fn mul(&mut self, mul: &GT) {
        self.mul_assign(mul)
    }

    fn pick<R: RngCore>(&mut self, rng: &mut R) {
        *self = ff::Field::random(rng)
    }
}

// TODO rename to G1
pub type Curve = CF<Scalar, G1>;
pub type G2Curve = CF<Scalar, G2>;
#[derive(Debug, Clone)]
pub struct TrialCurve {}
impl C for TrialCurve {
    type Scalar = Scalar;
    type Point = G1;
}

pub struct PairingCurve;

impl PC for PairingCurve {
    type Scalar = Scalar;
    type G1 = G1;
    type G2 = G2;
    type GT = Fq12;
    fn pair(a: &Self::G1, b: &Self::G2) -> Self::GT {
        Bls12::pairing(a.into_affine(), b.into_affine())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    //use rand::{SeedableRng, XorShiftRng};
    use rand::prelude::*;

    use serde::{de::DeserializeOwned, Serialize};
    use static_assertions::assert_impl_all;

    assert_impl_all!(G1: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(G2: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(GT: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(Scalar: Serialize, DeserializeOwned, Clone);

    // test if the element trait is usable
    fn add_two<T: Element>(e1: &mut T, e2: &T) {
        e1.add(e2);
        e1.mul(e2);
    }

    #[test]
    fn basic_group() {
        let mut s = Scalar::new();
        s.pick(&mut thread_rng());
        let mut e1 = s.clone();
        let e2 = s.clone();
        let mut s2 = s.clone();
        s2.add(&s);
        s2.mul(&s);
        add_two(&mut e1, &e2);
        // p1 = s2 * G = (s+s)G
        let mut p1 = G1::new();
        p1.mul(&s2);
        // p2 = sG + sG = s2 * G
        let mut p2 = G1::new();
        p2.mul(&s);
        p2.add(&p2.clone());
        assert_eq!(p1, p2);

        let mut ii = Scalar::new();
        ii.set_int(4);
    }
}
