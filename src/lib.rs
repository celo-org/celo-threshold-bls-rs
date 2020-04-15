use std::convert::TryInto;

pub mod curve;
pub mod dkg;
pub mod ecies;
pub mod group;
pub mod poly;
pub mod sig;
pub use group::*;

#[cfg(feature = "wasm")]
pub mod wasm;

use serde::{Deserialize, Serialize};

pub type Index = poly::Idx;

pub type DistPublic<C> = poly::PublicPoly<C>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "S: Serialize + serde::de::DeserializeOwned")]
pub struct Share<S: group::Scalar> {
    index: Index,
    private: S,
}

impl<S: group::Scalar> Share<S> {
    pub fn new(index: Index, private: S) -> Self {
        Self { index, private }
    }
}

impl<S> Encodable for Share<S>
where
    S: Scalar,
{
    fn marshal_len() -> usize {
        <S as Encodable>::marshal_len() + std::mem::size_of::<Index>()
    }

    fn marshal(&self) -> Vec<u8> {
        let mut bytes = self.index.to_le_bytes().to_vec();
        let pk_bytes = self.private.marshal();
        bytes.extend_from_slice(&pk_bytes);
        bytes
    }

    fn unmarshal(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let (int_bytes, rest) = data.split_at(std::mem::size_of::<Index>());
        let index = u32::from_le_bytes(int_bytes.try_into()?);

        self.index = index;
        self.private.unmarshal(rest)?;

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
