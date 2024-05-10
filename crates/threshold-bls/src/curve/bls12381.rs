use crate::group::PrimeOrder;
use crate::group::{self, Element, PairingCurve as PC, Point, Scalar as Sc};
use ark_bls12_381 as bls381;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::{HashToCurve, HashToCurveError};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use rand_core::RngCore;
use serde::{
    de::{Error as DeserializeError, SeqAccess, Visitor},
    ser::{Error as SerializationError, SerializeTuple},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::Sha256;
use std::{
    fmt,
    marker::PhantomData,
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};

/// Domain separator for signing messages
pub const SIG_DOMAIN: &[u8] = b"ULforxof";

// TODO(gakonst): Make this work with any Pairing.

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub struct Scalar(
    #[serde(deserialize_with = "deserialize_field")]
    #[serde(serialize_with = "serialize_field")]
    <bls381::Bls12_381 as Pairing>::ScalarField,
);

type ZG1 = <bls381::Bls12_381 as Pairing>::G1;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct G1(
    #[serde(deserialize_with = "deserialize_group")]
    #[serde(serialize_with = "serialize_group")]
    ZG1,
);

type ZG2 = <bls381::Bls12_381 as Pairing>::G2;

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
    <bls381::Bls12_381 as Pairing>::TargetField,
);

impl Element for Scalar {
    type RHS = Scalar;

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

    fn rand<R: rand_core::RngCore>(rng: &mut R) -> Self {
        Self(bls381::Fr::rand(rng))
    }
}

impl Sc for Scalar {
    fn set_int(&mut self, i: u64) {
        *self = Self(bls381::Fr::from(i))
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

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        let fr = bls381::Fr::from_random_bytes(bytes)?;
        Some(Self(fr))
    }

    fn serialized_size(&self) -> usize {
        self.0.serialized_size(Compress::Yes)
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

/// G1 points can be multiplied by Fr elements
impl Element for G1 {
    type RHS = Scalar;

    fn new() -> Self {
        Self(Zero::zero())
    }

    fn one() -> Self {
        Self(ZG1::generator())
    }

    fn rand<R: RngCore>(rng: &mut R) -> Self {
        Self(ZG1::rand(rng))
    }

    fn add(&mut self, s2: &Self) {
        self.0.add_assign(s2.0);
    }

    fn mul(&mut self, mul: &Scalar) {
        self.0.mul_assign(mul.0);
    }
}

/// Implementation of Point using G1 from BLS12-377
impl Point for G1 {
    type Error = HashToCurveError;

    fn map(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let hasher = MapToCurveBasedHasher::<
            ZG1,
            DefaultFieldHasher<Sha256>,
            WBMap<bls381::g1::Config>,
        >::new(SIG_DOMAIN)?;

        let hash = hasher.hash(data)?;

        *self = Self(hash.into());

        Ok(())
    }
}

impl fmt::Display for G1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

/// G1 points can be multiplied by Fr elements
impl Element for G2 {
    type RHS = Scalar;

    fn new() -> Self {
        Self(Zero::zero())
    }

    fn one() -> Self {
        Self(ZG2::generator())
    }

    fn rand<R: RngCore>(mut rng: &mut R) -> Self {
        Self(ZG2::rand(&mut rng))
    }

    fn add(&mut self, s2: &Self) {
        self.0.add_assign(s2.0);
    }

    fn mul(&mut self, mul: &Scalar) {
        self.0.mul_assign(mul.0)
    }
}

/// Implementation of Point using G2 from BLS12-377
impl Point for G2 {
    type Error = HashToCurveError;

    fn map(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let hasher = MapToCurveBasedHasher::<
            ZG2,
            DefaultFieldHasher<sha2::Sha256>,
            WBMap<bls381::g2::Config>,
        >::new(SIG_DOMAIN)?;

        let hash = hasher.hash(data)?;
        *self = Self(hash.into());

        Ok(())
    }
}

impl fmt::Display for G2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

//TODO (michael) : This interface should be refactored, GT is multiplicative subgroup of extension field
// so using elliptic curve additive notation for it doesn't make sense
impl Element for GT {
    type RHS = Scalar;

    fn new() -> Self {
        Self(One::one())
    }
    fn one() -> Self {
        Self(One::one())
    }
    fn add(&mut self, s2: &Self) {
        self.0.mul_assign(s2.0);
    }
    fn mul(&mut self, mul: &Scalar) {
        let scalar = mul.0.into_bigint();
        let mut res = Self::one();
        let mut temp = self.clone();
        for b in ark_ff::BitIteratorLE::without_trailing_zeros(scalar) {
            if b {
                res.0.mul_assign(temp.0);
            }
            temp.0.square_in_place();
        }
        *self = res.clone();
    }
    fn rand<R: RngCore>(rng: &mut R) -> Self {
        Self(bls381::Fq12::rand(rng))
    }
}

// TODO (michael): Write unit test for this
impl PrimeOrder for GT {
    fn in_correct_subgroup(&self) -> bool {
        self.0
            .pow(<bls381::Bls12_381 as Pairing>::ScalarField::characteristic())
            .is_one()
    }
}

impl fmt::Display for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{{:?}}}", self.0)
    }
}

pub type G1Curve = group::G1Curve<PairingCurve>;
pub type G2Curve = group::G2Curve<PairingCurve>;

#[derive(Clone, Debug)]
pub struct PairingCurve;

impl PC for PairingCurve {
    type Scalar = Scalar;
    type G1 = G1;
    type G2 = G2;
    type GT = GT;

    fn pair(a: &Self::G1, b: &Self::G2) -> Self::GT {
        GT(<bls381::Bls12_381 as Pairing>::pairing(a.0, b.0).0)
    }
}

// Serde implementations (ideally, these should be upstreamed to Zexe)

fn deserialize_field<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: Field,
{
    struct FieldVisitor<C>(PhantomData<C>);

    impl<'de, C> Visitor<'de> for FieldVisitor<C>
    where
        C: Field,
    {
        type Value = C;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid group element")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<C, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let len = C::zero().serialized_size(Compress::Yes);
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seq.next_element()?
                        .ok_or_else(|| DeserializeError::custom("could not read bytes"))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let res =
                C::deserialize_compressed(&mut &bytes[..]).map_err(DeserializeError::custom)?;
            Ok(res)
        }
    }

    let visitor = FieldVisitor(PhantomData);
    deserializer.deserialize_tuple(C::zero().serialized_size(Compress::Yes), visitor)
}

fn serialize_field<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: Field,
{
    let len = c.serialized_size(Compress::Yes);
    let mut bytes = Vec::with_capacity(len);
    c.serialize_compressed(&mut bytes)
        .map_err(SerializationError::custom)?;

    let mut tup = s.serialize_tuple(len)?;
    for byte in &bytes {
        tup.serialize_element(byte)?;
    }
    tup.end()
}

fn deserialize_group<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: CurveGroup,
    C::Affine: CanonicalDeserialize + CanonicalSerialize,
{
    struct GroupVisitor<C>(PhantomData<C>);

    impl<'de, C> Visitor<'de> for GroupVisitor<C>
    where
        C: CurveGroup,
        //C::Affine: CanonicalDeserialize + CanonicalSerialize,
    {
        type Value = C;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid group element")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<C, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let len = C::Affine::zero().serialized_size(Compress::Yes); //C::Affine::SERIALIZED_SIZE;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seq.next_element()?
                        .ok_or_else(|| DeserializeError::custom("could not read bytes"))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let affine = C::Affine::deserialize_compressed(&mut &bytes[..])
                .map_err(DeserializeError::custom)?;
            Ok(affine.into())
        }
    }

    let visitor = GroupVisitor(PhantomData);
    deserializer.deserialize_tuple(C::Affine::zero().serialized_size(Compress::Yes), visitor)
}

fn serialize_group<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    C: CurveGroup,
    C::Affine: CanonicalSerialize,
{
    let affine = c.into_affine();
    let len = affine.serialized_size(Compress::Yes);
    let mut bytes = Vec::with_capacity(len);
    affine
        .serialize_compressed(&mut bytes)
        .map_err(SerializationError::custom)?;

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

    fn serialize_group_test<E: Element>(size: usize) {
        let rng = &mut rand::thread_rng();
        let sig = E::rand(rng);
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
        let sig = E::rand(rng);
        let ser = bincode::serialize(&sig).unwrap();
        assert_eq!(ser.len(), size);

        let de: E = bincode::deserialize(&ser).unwrap();
        assert_eq!(de, sig);
    }

    #[test]
    fn gt_exp() {
        let rng = &mut rand::thread_rng();
        let base = GT::rand(rng);

        let mut sc = Scalar::one();
        sc.add(&Scalar::one());
        sc.add(&Scalar::one());

        let mut exp = base.clone();
        exp.mul(&sc);

        let mut res = base.clone();
        res.add(&base);
        res.add(&base);

        assert_eq!(exp, res);
    }
}
