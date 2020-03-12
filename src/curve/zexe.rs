use crate::group::{Element, Encodable, Scalar as Sc};
use algebra::bls12_377 as zexe;
use algebra::bytes::{FromBytes, ToBytes};
use algebra::curves::models::bls12::Bls12;
use algebra::curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use algebra::fields::Field;
use algebra::prelude::{One, UniformRand, Zero};
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
/*impl Point<Fr> for G1 {*/
//fn map(&mut self, data: &[u8]) {
//*self = G1::hash(data);
//}
/*}*/

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
/*impl Point<Fr> for G1 {*/
//fn map(&mut self, data: &[u8]) {
//*self = G1::hash(data);
//}
/*}*/

impl fmt::Display for G2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    //use rand::{SeedableRng, XorShiftRng};
    use rand::prelude::*;

    #[test]
    fn size377() {
        println!("scalar len: {}", Scalar::one().marshal().len());
        println!("g1 len: {}", G1::one().marshal().len());
        println!("g2 len: {}", G2::one().marshal().len());
    }
}
