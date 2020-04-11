pub mod curve;
pub mod dkg;
pub mod ecies;
pub mod group;
pub mod poly;
pub mod sig;
pub use group::*;

use serde::{Deserialize, Serialize};

pub type Index = poly::Idx;

//
pub type DistPublic<C> = poly::PublicPoly<C>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "S: Serialize + serde::de::DeserializeOwned")]
pub struct Share<S: group::Scalar> {
    index: Index,
    private: S,
}
