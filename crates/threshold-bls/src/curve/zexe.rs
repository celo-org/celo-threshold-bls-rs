use crate::group::{Curve, CurveFrom, Element, PairingCurve as PC, Point, Scalar as Sc};
use algebra::{
    bls12_377 as zexe,
    curves::{AffineCurve, PairingEngine, ProjectiveCurve},
    fields::Field,
    prelude::{One, UniformRand, Zero},
    CanonicalDeserialize, CanonicalSerialize, ConstantSerializedSize,
};
use bls_crypto::{
    hash_to_curve::{try_and_increment::TryAndIncrement, HashToCurve},
    hashers::DirectHasher,
    BLSError, SIG_DOMAIN,
};
use rand_core::RngCore;
use serde::{
    de::{Error as DeserializeError, SeqAccess, Visitor},
    ser::{Error as SerializationError, SerializeTuple},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt,
    marker::PhantomData,
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZexeError {
    #[error("{0}")]
    SerializationError(#[from] algebra::SerializationError),
    #[error("{0}")]
    BLSError(#[from] BLSError),
}

// TODO(gakonst): Make this work with any PairingEngine.

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Scalar(
    #[serde(deserialize_with = "deserialize_field")]
    #[serde(serialize_with = "serialize_field")]
    <zexe::Bls12_377 as PairingEngine>::Fr,
);

type ZG1 = <zexe::Bls12_377 as PairingEngine>::G1Projective;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct G1(
    #[serde(deserialize_with = "deserialize_group")]
    #[serde(serialize_with = "serialize_group")]
    ZG1,
);

type ZG2 = <zexe::Bls12_377 as PairingEngine>::G2Projective;

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

/// Implementation of Point using G1 from BLS12-377
impl Point<Scalar> for G1 {
    type Error = ZexeError;

    fn map(&mut self, data: &[u8]) -> Result<(), ZexeError> {
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

/// Implementation of Point using G2 from BLS12-377
impl Point<Scalar> for G2 {
    type Error = ZexeError;

    fn map(&mut self, data: &[u8]) -> Result<(), ZexeError> {
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

#[derive(Clone, Debug)]
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

// Serde implementations (ideally, these should be upstreamed to Zexe)

fn deserialize_field<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: CanonicalDeserialize + ConstantSerializedSize,
{
    struct FieldVisitor<C>(PhantomData<C>);

    impl<'de, C> Visitor<'de> for FieldVisitor<C>
    where
        C: CanonicalDeserialize + ConstantSerializedSize,
    {
        type Value = C;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid group element")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<C, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let len = C::SERIALIZED_SIZE;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seq.next_element()?
                        .ok_or(DeserializeError::custom("could not read bytes"))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let res =
                C::deserialize(&mut &bytes[..]).map_err(|err| DeserializeError::custom(err))?;
            Ok(res)
        }
    }

    let visitor = FieldVisitor(PhantomData);
    deserializer.deserialize_tuple(C::SERIALIZED_SIZE, visitor)
}

fn serialize_field<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: CanonicalSerialize,
{
    let len = c.serialized_size();
    let mut bytes = Vec::with_capacity(len);
    c.serialize(&mut bytes)
        .map_err(|err| SerializationError::custom(err))?;

    let mut tup = s.serialize_tuple(len)?;
    for byte in &bytes {
        tup.serialize_element(byte)?;
    }
    tup.end()
}

fn deserialize_group<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: ProjectiveCurve,
    C::Affine: CanonicalDeserialize + ConstantSerializedSize,
{
    struct GroupVisitor<C>(PhantomData<C>);

    impl<'de, C> Visitor<'de> for GroupVisitor<C>
    where
        C: ProjectiveCurve,
        C::Affine: CanonicalDeserialize + ConstantSerializedSize,
    {
        type Value = C;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid group element")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<C, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let len = C::Affine::SERIALIZED_SIZE;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seq.next_element()?
                        .ok_or(DeserializeError::custom("could not read bytes"))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let affine = C::Affine::deserialize(&mut &bytes[..])
                .map_err(|err| DeserializeError::custom(err))?;
            Ok(affine.into_projective())
        }
    }

    let visitor = GroupVisitor(PhantomData);
    deserializer.deserialize_tuple(C::Affine::SERIALIZED_SIZE, visitor)
}

fn serialize_group<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: ProjectiveCurve,
    C::Affine: CanonicalSerialize,
{
    let affine = c.into_affine();
    let len = affine.serialized_size();
    let mut bytes = Vec::with_capacity(len);
    affine
        .serialize(&mut bytes)
        .map_err(|err| SerializationError::custom(err))?;

    let mut tup = s.serialize_tuple(len)?;
    for byte in &bytes {
        tup.serialize_element(byte)?;
    }
    tup.end()
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
    fn serialize_group() {
        serialize_group_test::<G1>(48);
        serialize_group_test::<G2>(96);
    }

    fn serialize_group_test<E: Element<Scalar>>(size: usize) {
        let rng = &mut rand::thread_rng();
        let mut sig = E::new();
        sig.pick(rng);
        let ser = bincode::serialize(&sig).unwrap();
        assert_eq!(ser.len(), size);

        let de: E = bincode::deserialize(&ser).unwrap();
        assert_eq!(de, sig);
    }

    #[test]
    fn serialize_field() {
        serialize_field_test::<GT>(576);
        serialize_field_test::<Scalar>(32);
    }

    fn serialize_field_test<E: Element>(size: usize) {
        let rng = &mut rand::thread_rng();
        let mut sig = E::new();
        sig.pick(rng);
        let ser = bincode::serialize(&sig).unwrap();
        assert_eq!(ser.len(), size);

        let de: E = bincode::deserialize(&ser).unwrap();
        assert_eq!(de, sig);
    }
}
