/// # Board
///
/// A board is where DKG participants publish their data for the corresponding DKG
/// phase.
use super::primitives::{BundledJustification, BundledResponses, BundledShares};
use threshold_bls::group::Curve;
use bincode::serialize_into;
use std::io::Write;

/// Trait which must be implemented for writing to the board. This trait assumes
/// an authenticated channel.
pub trait BoardPublisher<C: Curve> {
    type Error;

    /// Publishes the shares to the board
    fn publish_shares(&mut self, shares: BundledShares<C>) -> Result<(), Self::Error>;

    /// Publishes the responses to the board
    fn publish_responses(&mut self, responses: BundledResponses) -> Result<(), Self::Error>;

    /// Publishes the justifications to the board
    fn publish_justifications(
        &mut self,
        justifications: BundledJustification<C>,
    ) -> Result<(), Self::Error>;

}

// Board implementation for all `Write` implementers, leveraging serde/bincode
impl <C: Curve, W: Write> BoardPublisher<C> for W {
    type Error = bincode::Error;

    fn publish_shares(&mut self, shares: BundledShares<C>) -> Result<(), Self::Error> {
        serialize_into(self, &shares)
    }

    fn publish_responses(&mut self, responses: BundledResponses) -> Result<(), Self::Error> {
        serialize_into(self, &responses)
    }

    fn publish_justifications(
        &mut self,
        justifications: BundledJustification<C>,
    ) -> Result<(), Self::Error> {
        serialize_into(self, &justifications)
    }

}
