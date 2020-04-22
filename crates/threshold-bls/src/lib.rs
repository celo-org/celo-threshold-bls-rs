use std::{convert::TryInto, fmt::Debug};

pub mod curve;
pub mod ecies;
pub mod group;
pub mod poly;
pub mod sig;
pub use group::*;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Index = poly::Idx;

pub type DistPublic<C> = poly::PublicPoly<C>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "S: Serialize + serde::de::DeserializeOwned")]
pub struct Share<S: Scalar> {
    pub index: Index,
    pub private: S,
}

impl<S: Scalar> Share<S> {
    pub fn new(index: Index, private: S) -> Self {
        Self { index, private }
    }
}

#[derive(Debug, Error)]
pub enum ShareError<E: Encodable + Debug> {
    #[error("could not deserialize index: {0}")]
    IndexError(#[from] std::array::TryFromSliceError),
    #[error("could not deserialize scalar: {0}")]
    EncodableError(E::Error),
}

impl<S> Encodable for Share<S>
where
    S: Scalar,
{
    type Error = ShareError<S>;

    fn marshal_len() -> usize {
        <S as Encodable>::marshal_len() + std::mem::size_of::<Index>()
    }

    fn marshal(&self) -> Vec<u8> {
        let mut bytes = self.index.to_le_bytes().to_vec();
        let pk_bytes = self.private.marshal();
        bytes.extend_from_slice(&pk_bytes);
        bytes
    }

    fn unmarshal(&mut self, data: &[u8]) -> Result<(), ShareError<S>> {
        let (int_bytes, rest) = data.split_at(std::mem::size_of::<Index>());
        let index = u32::from_le_bytes(int_bytes.try_into()?);

        self.index = index;
        self.private
            .unmarshal(rest)
            // We cannot implement `From` for ScalarError because it is generic
            // and results in `conflicting From<T> for T` implementations
            .map_err(ShareError::EncodableError)?;

        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "bls12_377")]
mod tests {
    use super::*;
    use group::Encodable;

    use curve::zexe::Scalar;

    #[test]
    fn share_serialization() {
        let rng = &mut rand::thread_rng();
        for _ in 0..100 {
            let mut pk = Scalar::new();
            pk.pick(rng);

            let share = Share {
                index: rand::random(),
                private: pk,
            };

            let ser = share.marshal();
            let mut de = Share::new(0, Scalar::new());
            de.unmarshal(&ser).unwrap();

            assert_eq!(share, de);
        }
    }
}
