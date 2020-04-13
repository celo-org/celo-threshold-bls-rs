use crate::group::{Curve, CurveFrom, Element, Encodable, PairingCurve as PC, Point, Scalar as Sc};
use algebra::{
    bls12_377 as zexe,
    bytes::{FromBytes, ToBytes},
    curves::{AffineCurve, PairingEngine, ProjectiveCurve},
    fields::Field,
    prelude::{One, UniformRand, Zero},
};
use bls_crypto::{
    hash_to_curve::{try_and_increment::TryAndIncrement, HashToCurve},
    hashers::DirectHasher,
    SIG_DOMAIN,
};
use rand_core::RngCore;
use std::error::Error;
use std::fmt;
use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Scalar(<zexe::Bls12_377 as PairingEngine>::Fr);

type ZG1 = <zexe::Bls12_377 as PairingEngine>::G1Projective;
type ZG1A = <zexe::Bls12_377 as PairingEngine>::G1Affine;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct G1(ZG1);

type ZG2 = <zexe::Bls12_377 as PairingEngine>::G2Projective;
type ZG2A = <zexe::Bls12_377 as PairingEngine>::G2Affine;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct G2(ZG2);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GT(<zexe::Bls12_377 as PairingEngine>::Fqk);

impl Element<Scalar> for Scalar {
    fn new() -> Self {
        Self(Zero::zero())
    }
    fn one() -> Self {
        Self(One::one())
    }
    fn add(&mut self, s2: &Self) {
        self.0.add_assign(s2.0);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.0.mul_assign(mul.0)
    }
    fn pick<R: RngCore>(&mut self, mut rng: &mut R) {
        *self = Self(zexe::Fr::rand(&mut rng))
    }
}

impl Encodable for Scalar {
    fn marshal_len() -> usize {
        32
    }
    fn marshal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        self.0
            .write(&mut out)
            .expect("writing to buff should not fail");
        out
    }

    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        match zexe::Fr::read(data) {
            Ok(fr) => {
                *self = Self(fr);
                Ok(())
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Sc for Scalar {
    fn set_int(&mut self, i: u64) {
        *self = Self(zexe::Fr::from(i))
    }

    fn inverse(&self) -> Option<Self> {
        Some(Self(Field::inverse(&self.0)?))
    }

    fn negate(&mut self) {
        *self = Self(self.0.neg())
    }

    fn sub(&mut self, other: &Self) {
        self.0.sub_assign(other.0);
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

/// G1 points can be multiplied by Fr elements
impl Element<Scalar> for G1 {
    fn new() -> Self {
        Self(Zero::zero())
    }

    fn one() -> Self {
        Self(ZG1::prime_subgroup_generator())
    }

    fn pick<R: RngCore>(&mut self, mut rng: &mut R) {
        self.0 = ZG1::rand(&mut rng)
    }
    fn add(&mut self, s2: &Self) {
        self.0.add_assign(s2.0);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.0.mul_assign(mul.0)
    }
}

impl Encodable for G1 {
    fn marshal_len() -> usize {
        97
    }
    fn marshal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(144);
        self.0
            .into_affine()
            .write(&mut out)
            .expect("writing to vector should not fail");
        out
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        match ZG1A::read(data) {
            Ok(g) => {
                self.0 = g.into_projective();
                Ok(())
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}

/// Implementation of Point using G1 from BLS12-377
impl Point<Scalar> for G1 {
    fn map(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let hasher = TryAndIncrement::new(&DirectHasher);

        let hash = hasher.hash(SIG_DOMAIN, data, &vec![])?;

        *self = Self(hash);

        Ok(())
    }
}

impl fmt::Display for G1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

/// G1 points can be multiplied by Fr elements
impl Element<Scalar> for G2 {
    fn new() -> Self {
        Self(Zero::zero())
    }

    fn one() -> Self {
        Self(ZG2::prime_subgroup_generator())
    }

    fn pick<R: RngCore>(&mut self, mut rng: &mut R) {
        self.0 = ZG2::rand(&mut rng)
    }
    fn add(&mut self, s2: &Self) {
        self.0.add_assign(s2.0);
    }
    fn mul(&mut self, mul: &Scalar) {
        self.0.mul_assign(mul.0)
    }
}

impl Encodable for G2 {
    fn marshal_len() -> usize {
        return 193;
    }
    fn marshal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(144);
        self.0
            .into_affine()
            .write(&mut out)
            .expect("writing to vector should not fail");
        out
    }
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        match ZG2A::read(data) {
            Ok(g) => {
                self.0 = g.into_projective();
                Ok(())
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}

/// Implementation of Point using G2 from BLS12-377
impl Point<Scalar> for G2 {
    fn map(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let hasher = TryAndIncrement::new(&DirectHasher);

        let hash = hasher.hash(SIG_DOMAIN, data, &vec![])?;
        *self = Self(hash);

        Ok(())
    }
}

impl fmt::Display for G2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

impl Element<GT> for GT {
    fn new() -> Self {
        Self(Zero::zero())
    }
    fn one() -> Self {
        Self(One::one())
    }
    fn add(&mut self, s2: &Self) {
        self.0.add_assign(s2.0);
    }
    fn mul(&mut self, mul: &GT) {
        self.0.mul_assign(mul.0)
    }
    fn pick<R: RngCore>(&mut self, mut rng: &mut R) {
        *self = Self(zexe::Fq12::rand(&mut rng))
    }
}

impl fmt::Display for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

pub type G1Curve = CurveFrom<Scalar, G1>;
//pub type G2Curve = CurveFrom<Scalar, G2>;
pub struct G2Curve {}
impl Curve for G2Curve {
    type Scalar = Scalar;
    type Point = G2;
}

pub struct PairingCurve {}

impl PC for PairingCurve {
    type Scalar = Scalar;
    type G1 = G1;
    type G2 = G2;
    type GT = GT;
    fn pair(a: &Self::G1, b: &Self::G2) -> Self::GT {
        GT(<zexe::Bls12_377 as PairingEngine>::pairing(a.0, b.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size377() {
        println!("scalar len: {}", Scalar::one().marshal().len());
        println!("g1 len: {}", G1::one().marshal().len());
        println!("g2 len: {}", G2::one().marshal().len());
    }
}
