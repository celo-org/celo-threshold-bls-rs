//! Traits for operating on Groups and Elliptic Curves.

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::marker::PhantomData;

/// Element represents an element of a group with the additive notation
/// which is also equipped with a multiplication transformation.
/// Two implementations are for Scalar which forms a ring so RHS is the same
/// and Point which can be multiplied by a scalar of its prime field.
pub trait Element:
    Clone + Display + Debug + Eq + Serialize + for<'a> Deserialize<'a> + PartialEq + Send + Sync
{
    /// The right-hand-side argument for multiplication
    type RHS;

    /// Returns the zero element of the group
    fn new() -> Self;

    /// Returns the one element of the group
    fn one() -> Self;

    /// Adds the RHS  element to the LHS element in place
    fn add(&mut self, s2: &Self);

    /// Multiplies the LHS element by the RHS element in place
    fn mul(&mut self, mul: &Self::RHS);

    /// Samples a random element using the provided RNG
    fn rand<R: RngCore>(rng: &mut R) -> Self;

    /// Returns the zero element of the group
    fn zero() -> Self {
        Self::new()
    }
}

/// Checks inclusion in prime order subgroup. Only needed when underlying trait
/// does not enforce this already
pub trait PrimeOrder: Element {
    /// Checks the provided element is in the correct prime-order subgroup
    fn in_correct_subgroup(&self) -> bool;
}

/// Scalar can be multiplied by only a Scalar, no other elements.
pub trait Scalar: Element {
    fn set_int(&mut self, i: u64);
    fn inverse(&self) -> Option<Self>;
    fn negate(&mut self);
    fn sub(&mut self, other: &Self);
    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;
    fn serialized_size(&self) -> usize;
}

/// Basic point functionality that can be multiplied by a scalar
pub trait Point: Element {
    /// Error which may occur while mapping to the group
    type Error: Debug;

    /// Maps the provided data to a group element
    fn map(&mut self, data: &[u8]) -> Result<(), <Self as Point>::Error>;
}

/// A group holds functionalities to create scalar and points related; it is
/// similar to the Engine definition, just much more simpler.
pub trait Curve: Clone + Debug + Send + Sync {
    /// The curve's scalar
    type Scalar: Scalar<RHS = Self::Scalar>;

    /// The curve's point
    type Point: Point<RHS = Self::Scalar>;

    /// scalar returns the identity element of the field.
    fn scalar() -> Self::Scalar {
        Self::Scalar::new()
    }

    /// point returns the default additive generator of the group.
    fn point() -> Self::Point {
        Self::Point::one()
    }
}

/// A curve equipped with a bilinear pairing operation.
pub trait PairingCurve: Debug {
    type Scalar: Scalar<RHS = Self::Scalar>;

    type G1: Point<RHS = Self::Scalar>;

    type G2: Point<RHS = Self::Scalar>;

    type GT: Element<RHS = Self::Scalar>;

    /// Perfors a pairing operation between the 2 group elements
    fn pair(a: &Self::G1, b: &Self::G2) -> Self::GT;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Helper which binds together a scalar with a group type to form a curve
pub struct CurveFrom<S: Scalar, P: Point> {
    s: PhantomData<S>,
    p: PhantomData<P>,
}

impl<S, P> Curve for CurveFrom<S, P>
where
    S: Scalar<RHS = S>,
    P: Point<RHS = S>,
{
    type Scalar = S;
    type Point = P;
}

pub(super) type G1Curve<C> = CurveFrom<<C as PairingCurve>::Scalar, <C as PairingCurve>::G1>;
pub(super) type G2Curve<C> = CurveFrom<<C as PairingCurve>::Scalar, <C as PairingCurve>::G2>;
