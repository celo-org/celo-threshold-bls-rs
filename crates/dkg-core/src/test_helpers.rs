use super::board::BoardPublisher;
use super::primitives::bundles::{BundledJustification, BundledResponses, BundledShares};
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

impl<C: Curve> BoardPublisher<C> for InMemoryBoard<C> {
    type Error = ();

    fn publish_shares(&mut self, bundle: BundledShares<C>) -> Result<(), Self::Error> {
        self.shares.push(bundle);
        Ok(())
    }

    fn publish_responses(&mut self, bundle: BundledResponses) -> Result<(), Self::Error> {
        self.responses.push(bundle);
        Ok(())
    }

    fn publish_justifications(
        &mut self,
        bundle: BundledJustification<C>,
    ) -> Result<(), Self::Error> {
        self.justifs.push(bundle);
        Ok(())
    }
}
