use crate::group::{Curve, CurveFrom, Element, Encodable, PairingCurve as PC, Point, Scalar as Sc};
use algebra::{
    bls12_377 as zexe,
    bytes::{FromBytes, ToBytes},
    curves::{AffineCurve, PairingEngine, ProjectiveCurve},
    fields::Field,
    prelude::{One, UniformRand, Zero},
    CanonicalDeserialize, CanonicalSerialize,
};
use bls_crypto::{
    hash_to_curve::{try_and_increment::TryAndIncrement, HashToCurve},
    hashers::DirectHasher,
    SIG_DOMAIN,
};
use rand_core::RngCore;
use serde::Serialize;
use serde::{
    de::Error as DeserializeError, ser::Error as SerializationError, Deserialize, Deserializer,
    Serializer,
};
use std::error::Error;
use std::fmt;
use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Scalar(
    #[serde(deserialize_with = "deserialize_field")]
    #[serde(serialize_with = "serialize_field")]
    <zexe::Bls12_377 as PairingEngine>::Fr,
);

type ZG1 = <zexe::Bls12_377 as PairingEngine>::G1Projective;
type ZG1A = <zexe::Bls12_377 as PairingEngine>::G1Affine;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct G1(
    #[serde(deserialize_with = "deserialize_group")]
    #[serde(serialize_with = "serialize_group")]
    ZG1,
);

type ZG2 = <zexe::Bls12_377 as PairingEngine>::G2Projective;
type ZG2A = <zexe::Bls12_377 as PairingEngine>::G2Affine;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct G2(
    #[serde(deserialize_with = "deserialize_group")]
    #[serde(serialize_with = "serialize_group")]
    ZG2,
);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GT(
    #[serde(deserialize_with = "deserialize_field")]
    #[serde(serialize_with = "serialize_field")]
    <zexe::Bls12_377 as PairingEngine>::Fqk,
);

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
#[derive(Clone, Debug)]
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

// Serde implementations

fn deserialize_field<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: CanonicalDeserialize,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    C::deserialize(&mut &bytes[..]).map_err(|err| DeserializeError::custom(err))
}

fn serialize_field<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: CanonicalSerialize,
{
    let mut bytes = vec![0; c.serialized_size()];
    c.serialize(&mut &mut bytes[..])
        .map_err(|err| SerializationError::custom(err))?;
    s.serialize_bytes(&bytes)
}

fn deserialize_group<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: ProjectiveCurve,
    C::Affine: CanonicalDeserialize,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    let affine =
        C::Affine::deserialize(&mut &bytes[..]).map_err(|err| DeserializeError::custom(err))?;
    Ok(affine.into_projective())
}

fn serialize_group<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: ProjectiveCurve,
    C::Affine: CanonicalSerialize,
{
    let affine = c.into_affine();
    let mut bytes = vec![0; affine.serialized_size()];
    affine
        .serialize(&mut &mut bytes[..])
        .map_err(|err| SerializationError::custom(err))?;
    s.serialize_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{de::DeserializeOwned, Serialize};
    use static_assertions::assert_impl_all;

    assert_impl_all!(G1: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(G2: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(GT: Serialize, DeserializeOwned, Clone);
    assert_impl_all!(Scalar: Serialize, DeserializeOwned, Clone);

    #[test]
    fn size377() {
        println!("scalar len: {}", Scalar::one().marshal().len());
        println!("g1 len: {}", G1::one().marshal().len());
        println!("g2 len: {}", G2::one().marshal().len());
    }
}
