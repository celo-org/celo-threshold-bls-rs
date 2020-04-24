use serde::{Deserialize, Serialize};

pub mod curve;
pub mod ecies;
pub mod group;
pub mod poly;
pub mod sig;
pub use group::*;

pub type Index = poly::Idx;

pub type DistPublic<C> = poly::PublicPoly<C>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Share<S> {
    pub index: Index,
    pub private: S,
}

impl<S: Scalar> Share<S> {
    pub fn new(index: Index, private: S) -> Self {
        Self { index, private }
    }
}
