use super::board::BoardPublisher;
use super::primitives::types::{BundledJustification, BundledResponses, BundledShares};
use async_trait::async_trait;
use threshold_bls::group::Curve;

/// An in-memory board used for testing
pub struct InMemoryBoard<C: Curve> {
    pub shares: Vec<BundledShares<C>>,
    pub responses: Vec<BundledResponses>,
    pub justifs: Vec<BundledJustification<C>>,
}

impl<C: Curve> InMemoryBoard<C> {
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            shares: vec![],
            responses: vec![],
            justifs: vec![],
        }
    }
}

#[async_trait(?Send)]
impl<C: Curve> BoardPublisher<C> for InMemoryBoard<C> {
    type Error = ();

    async fn publish_shares(&mut self, bundle: BundledShares<C>) -> Result<(), Self::Error>
    where
        C: 'async_trait,
    {
        self.shares.push(bundle);
        Ok(())
    }

    async fn publish_responses(&mut self, bundle: BundledResponses) -> Result<(), Self::Error>
    where
        C: 'async_trait,
    {
        self.responses.push(bundle);
        Ok(())
    }

    async fn publish_justifications(
        &mut self,
        bundle: BundledJustification<C>,
    ) -> Result<(), Self::Error>
    where
        C: 'async_trait,
    {
        self.justifs.push(bundle);
        Ok(())
    }
}
