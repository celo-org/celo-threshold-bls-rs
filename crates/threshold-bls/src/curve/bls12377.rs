use crate::group::{self, Element, PairingCurve as PC, Point, PrimeOrder, Scalar as Sc};

use ark_bls12_377 as bls377;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
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

/// Domain separator for signing messages
const SIG_DOMAIN: &[u8] = b"ULforxof";

#[derive(Debug, Error)]
pub enum BLSError {
    #[error("{0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Could not hash to curve")]
    HashToCurveError,
    #[error("domain length is too large: {0}")]
    DomainTooLarge(usize),
}

/// Encodes the XOF digest length into the node offset field used by Blake2s/Blake2x.
fn xof_digest_length_to_node_offset(node_offset: u64, xof_digest_length: usize) -> u64 {
    let bytes = (xof_digest_length as u16).to_le_bytes();
    node_offset | ((bytes[0] as u64) << 32) | ((bytes[1] as u64) << 40)
}

/// Blake2s CRH followed by Blake2x XOF expansion.
///
/// This is equivalent to `bls-crypto`'s `DirectHasher::hash()`.
fn blake2_hash(
    domain: &[u8],
    message: &[u8],
    output_size_in_bytes: usize,
) -> Result<Vec<u8>, BLSError> {
    if domain.len() > 8 {
        return Err(BLSError::DomainTooLarge(domain.len()));
    }

    // CRH step: compress the message with Blake2s
    let hashed = blake2s_simd::Params::new()
        .hash_length(32)
        .node_offset(xof_digest_length_to_node_offset(0, output_size_in_bytes))
        .personal(domain)
        .to_state()
        .update(message)
        .finalize()
        .as_ref()
        .to_vec();

    // XOF step: expand the compressed hash to the desired output length
    let num_hashes = output_size_in_bytes.div_ceil(32);
    let mut result = Vec::with_capacity(output_size_in_bytes);
    for i in 0..num_hashes {
        let hash_length = if i == num_hashes - 1 && (output_size_in_bytes % 32 != 0) {
            output_size_in_bytes % 32
        } else {
            32
        };
        let hash_result = blake2s_simd::Params::new()
            .hash_length(hash_length)
            .max_leaf_length(32)
            .inner_hash_length(32)
            .fanout(0)
            .max_depth(0)
            .personal(domain)
            .node_offset(xof_digest_length_to_node_offset(
                i as u64,
                output_size_in_bytes,
            ))
            .to_state()
            .update(&hashed)
            .finalize();
        result.extend_from_slice(hash_result.as_ref());
    }

    Ok(result)
}

// TODO(gakonst): Make this work with any Pairing.

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub struct Scalar(
    #[serde(deserialize_with = "deserialize_field")]
    #[serde(serialize_with = "serialize_field")]
    <bls377::Bls12_377 as Pairing>::ScalarField,
);

type ZG1 = <bls377::Bls12_377 as Pairing>::G1;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct G1(
    #[serde(deserialize_with = "deserialize_group")]
    #[serde(serialize_with = "serialize_group")]
    ZG1,
);

type ZG2 = <bls377::Bls12_377 as Pairing>::G2;

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
    <bls377::Bls12_377 as Pairing>::TargetField,
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

    fn rand<R: RngCore>(rng: &mut R) -> Self {
        Self(bls377::Fr::rand(rng))
    }
}

impl Sc for Scalar {
    fn set_int(&mut self, i: u64) {
        *self = Self(bls377::Fr::from(i))
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
        let fr = bls377::Fr::from_random_bytes(bytes)?;
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

/// Try-and-increment hash-to-curve that matches the original `algebra-core` crate's
/// behavior (scipr-lab/zexe at commit 9d267f65).
///
/// We bypass `bls-crypto`'s `TryAndIncrement` entirely because its `compat` feature
/// has two bugs:
/// 1. It assumes the old library extracted the y-sign flag from bit 1 of the last
///    byte. In reality, the old `algebra-core` used `from_random_bytes_with_flags`
///    which extracts flags from bits 7-6 (the standard SWFlags convention).
/// 2. The compat layer's bit 1 → bit 7 remapping introduces a wrong transformation.
///
/// We also can't use `ark-ec`'s `GroupAffine::from_random_bytes` directly because
/// it rejects candidates where both flag bits (7 and 6) are set, while the old code
/// accepted them as positive-y points.
///
/// This function replicates the old `algebra-core` behavior exactly:
/// - Checks bit 7 (`& 0x80`) of the last hash byte for the y-sign (positive = largest y)
/// - Parses x via `Field::from_random_bytes` (masks last byte to field bits)
/// - Never rejects based on the infinity flag in random hash bytes
fn try_and_increment_hash<P: SWCurveConfig>(
    domain: &[u8],
    message: &[u8],
    extra_data: &[u8],
) -> Result<Projective<P>, BLSError>
where
    P::BaseField: Field,
{
    let num_bytes = Affine::<P>::zero().serialized_size(Compress::Yes);
    // Round up to the nearest multiple of 256 bits (in bytes).
    let hash_bytes = {
        let bits = (num_bytes * 8) as f64 / 256.0;
        (bits.ceil() * 256.0) as usize / 8
    };

    for c in 0u8..=254 {
        let msg = [&[c][..], extra_data, message].concat();
        let candidate_hash = blake2_hash(domain, &msg, hash_bytes)?;

        // Replicate old algebra-core's from_random_bytes_with_flags behavior:
        // The flags byte is (last_byte & flags_mask) where flags_mask = 0xFE for
        // BLS12-377 Fq (REPR_SHAVE_BITS=7). The positive-y flag is bit 7.
        // Crucially, the old code never rejected candidates where both bits 7 and 6
        // were set — it just treated bit 7 as the y-sign regardless.
        let is_positive = candidate_hash[num_bytes - 1] & 0x80 != 0;

        // Parse x-coordinate. from_random_bytes masks the last byte for the modulus
        // (to & 0x01 for 377-bit Fq), matching the old behavior exactly.
        if let Some(x) = P::BaseField::from_random_bytes(&candidate_hash[..num_bytes]) {
            if let Some(p) = Affine::<P>::get_point_from_x_unchecked(x, is_positive) {
                let scaled = p.mul_by_cofactor_to_group();
                if !scaled.is_zero() {
                    return Ok(scaled);
                }
            }
        }
    }

    Err(BLSError::HashToCurveError)
}

/// Implementation of Point using G1 from BLS12-377
impl Point for G1 {
    type Error = BLSError;

    fn map(&mut self, data: &[u8]) -> Result<(), BLSError> {
        let hash = try_and_increment_hash::<
            <bls377::Config as ark_ec::bls12::Bls12Config>::G1Config,
        >(SIG_DOMAIN, data, &[])?;
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
impl Element for G2 {
    type RHS = Scalar;

    fn new() -> Self {
        Self(Zero::zero())
    }

    fn one() -> Self {
        Self(ZG2::generator())
    }

    fn rand<R: RngCore>(rng: &mut R) -> Self {
        Self(ZG2::rand(rng))
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
    type Error = BLSError;

    fn map(&mut self, data: &[u8]) -> Result<(), BLSError> {
        let hash = try_and_increment_hash::<
            <bls377::Config as ark_ec::bls12::Bls12Config>::G2Config,
        >(SIG_DOMAIN, data, &[])?;
        *self = Self(hash);
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
        // TODO(pl)
        // Self(Zero::zero())
        Self(One::one())
    }
    fn one() -> Self {
        Self(One::one())
    }
    // fn add(&mut self, s2: &Self) {
    //     self.0.add_assign(s2.0);
    // }
    // fn mul(&mut self, mul: &Scalar) {
    //     self.0.mul_assign(mul.0)
    // }
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
        Self(bls377::Fq12::rand(rng))
    }
}

// TODO (michael): Write unit test for this
impl PrimeOrder for GT {
    fn in_correct_subgroup(&self) -> bool {
        self.0
            .pow(<bls377::Bls12_377 as Pairing>::ScalarField::characteristic())
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
        GT(<bls377::Bls12_377 as Pairing>::pairing(a.0, b.0).0)
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
    {
        type Value = C;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid group element")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<C, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let len = C::Affine::zero().serialized_size(Compress::Yes);
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

    #[test]
    fn blake2_hash_test_vectors() {
        let test_vectors = [(
            "7f8a56d8b5fb1f038ffbfce79f185f4aad9d603094edb85457d6c84d6bc02a82644ee42da51e9c3bb18395f450092d39721c32e7f05ec4c1f22a8685fcb89721738335b57e4ee88a3b32df3762503aa98e4a9bd916ed385d265021391745f08b27c37dc7bc6cb603cc27e19baf47bf00a2ab2c32250c98d79d5e1170dee4068d9389d146786c2a0d1e08ade5",
            "87009aa74342449e10a3fd369e736fcb9ad1e7bd70ef007e6e2394b46c094074c86adf6c980be077fa6c4dc4af1ca0450a4f00cdd1a87e0c4f059f512832c2d92a1cde5de26d693ccd246a1530c0d6926185f9330d3524710b369f6d2976a44d",
        ), (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "57d5",
        ), (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "bfec8b58ee2e2e32008eb9d7d304914ea756ecb31879eb2318e066c182b0e77e6a518e366f345692e29f497515f799895983200f0d7dafa65c83a7506c03e8e5eee387cffdb27a0e6f5f3e9cb0ccbcfba827984586f608769f08f6b1a84872",
        )];
        for (input_hex, expected_hex) in &test_vectors {
            let bytes = blake2_hash(
                b"",
                &hex::decode(input_hex).unwrap(),
                expected_hex.len() / 2,
            )
            .unwrap();
            assert_eq!(hex::encode(&bytes), *expected_hex);
        }
    }

    #[test]
    fn hash_to_curve_g1() {
        use crate::group::Point;

        let cases: &[(&[u8], &str)] = &[
            (
                &[0x00; 32],
                "74e26c20c5eb368ff74dd85e454a965406c56195d3b99898edbe328920604eaa18c564878dab9de6813e10e172191600",
            ),
            (
                &[0x56; 32],
                "674ef6c1ef7d872f93492743a1b0d3e63a18a7508bbdf3a96d181933fa4e278b5977865b7be21fc1bac9849d485def00",
            ),
            (
                &[0xab; 32],
                "1b0e65aeec6946f9bf19d7958a8c92f8ec497dd96f457d58d521f0738428df57e7bce81ee38873dc47667d742ac56380",
            ),
        ];

        for (msg, expected_hex) in cases {
            let mut point = G1::new();
            point.map(msg).expect("hash to curve failed");
            let serialized = bincode::serialize(&point).unwrap();
            assert_eq!(hex::encode(&serialized), *expected_hex);
        }
    }
}
