pub mod curve;
pub mod dkg;
pub mod ecies;
pub mod group;
pub mod poly;
pub mod sig;
pub use group::*;

pub type Index = poly::Idx;

pub type DistPublic<C> = poly::PublicPoly<C>;

#[derive(Clone, Debug, PartialEq)]
pub struct Share<S: group::Scalar> {
    index: Index,
    private: S,
}
