//! Traits for operating on Groups and Elliptic Curves.

use rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{Debug, Display};
use std::marker::PhantomData;

/// Element represents an element of a group with the additive notation
/// which is also equipped with a multiplication transformation.
/// Two implementations are for Scalar which forms a ring so RHS is the same
/// and Point which can be multiplied by a scalar of its prime field.
pub trait Element<RHS = Self>: Clone + Display + Debug + Eq {
    /// new MUST return the zero element of the group.
    fn new() -> Self;
    fn one() -> Self;
    fn add(&mut self, s2: &Self);
    fn mul(&mut self, mul: &RHS);
    fn pick<R: RngCore>(&mut self, rng: &mut R);
    fn zero() -> Self {
        Self::new()
    }
}

/// Scalar can be multiplied by only a Scalar, no other elements.
// TODO: is that truly enforced by Rust ?
pub trait Scalar: Element + Encodable {
    fn set_int(&mut self, i: u64);
    fn inverse(&self) -> Option<Self>;
    fn negate(&mut self);
    fn sub(&mut self, other: &Self);
    // TODO
}

/// Basic point functionality that can be multiplied by a scalar
pub trait Point<A: Scalar>: Element<A> + Encodable {
    type Error: Debug;

    fn map(&mut self, data: &[u8]) -> Result<(), <Self as Point<A>>::Error>;
}

//type PPoint = Point<A: Scalar>;

/// A group holds functionalities to create scalar and points related; it is
/// similar to the Engine definition, just much more simpler.
pub trait Curve: Clone + Debug {
    type Scalar: Scalar;
    type Point: Point<Self::Scalar>;

    /// scalar returns the identity element of the field.
    fn scalar() -> Self::Scalar {
        Self::Scalar::new()
    }

    /// point returns the default additive generator of the group.
    fn point() -> Self::Point {
        Self::Point::one()
    }
}

pub trait PairingCurve: Debug {
    type Scalar: Scalar;
    type G1: Point<Self::Scalar> + Encodable;
    type G2: Point<Self::Scalar> + Encodable;
    type GT: Element;

    fn pair(a: &Self::G1, b: &Self::G2) -> Self::GT;
}

#[derive(Debug, Clone, PartialEq)]
pub struct CurveFrom<S: Scalar, P: Point<S>> {
    m: PhantomData<S>,
    mm: PhantomData<P>,
}

impl<S, P> Curve for CurveFrom<S, P>
where
    S: Scalar,
    P: Point<S>,
{
    type Scalar = S;
    type Point = P;
}

pub type G1Curve<C> = CurveFrom<<C as PairingCurve>::Scalar, <C as PairingCurve>::G1>;
pub type G2Curve<C> = CurveFrom<<C as PairingCurve>::Scalar, <C as PairingCurve>::G2>;

pub trait Encodable: Serialize + DeserializeOwned {
    type Error: std::error::Error;

    fn marshal_len() -> usize;
    fn marshal(&self) -> Vec<u8>;
    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}
