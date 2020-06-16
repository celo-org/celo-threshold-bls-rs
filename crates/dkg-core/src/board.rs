/// # Board
///
/// A board is where DKG participants publish their data for the corresponding DKG
/// phase.
use super::primitives::types::{BundledJustification, BundledResponses, BundledShares};
use async_trait::async_trait;
use bincode::serialize_into;
use std::io::Write;
use threshold_bls::group::Curve;

/// Trait which must be implemented for writing to the board. This trait assumes
/// an authenticated channel.
#[async_trait(?Send)]
pub trait BoardPublisher<C>
where
    C: Curve,
{
    /// Error raised when trying to publish data to the board
    type Error;

    /// Publishes the shares to the board
    async fn publish_shares(&mut self, shares: BundledShares<C>) -> Result<(), Self::Error>
    where
        C: 'async_trait;

    /// Publishes the responses to the board
    async fn publish_responses(&mut self, responses: BundledResponses) -> Result<(), Self::Error>
    where
        C: 'async_trait;

    /// Publishes the justifications to the board
    async fn publish_justifications(
        &mut self,
        justifications: BundledJustification<C>,
    ) -> Result<(), Self::Error>
    where
        C: 'async_trait;
}

// Board implementation for all `Write` implementers, leveraging serde/bincode
#[async_trait(?Send)]
impl<C, W> BoardPublisher<C> for W
where
    C: Curve,
    W: Write,
{
    /// Error raised when trying to publish data to the board
    type Error = bincode::Error;

    async fn publish_shares(&mut self, shares: BundledShares<C>) -> Result<(), Self::Error>
    where
        C: 'async_trait,
    {
        serialize_into(self, &shares)
    }

    async fn publish_responses(&mut self, responses: BundledResponses) -> Result<(), Self::Error>
    where
        C: 'async_trait,
    {
        serialize_into(self, &responses)
    }

    async fn publish_justifications(
        &mut self,
        justifications: BundledJustification<C>,
    ) -> Result<(), Self::Error>
    where
        C: 'async_trait,
    {
        serialize_into(self, &justifications)
    }
}
