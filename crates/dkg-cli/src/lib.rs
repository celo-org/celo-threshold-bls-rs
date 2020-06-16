pub mod actions;
mod dkg_contract;
pub mod opts;

use dkg_contract::DKG;
use ethers::{
    contract::ContractError,
    providers::{JsonRpcClient, ProviderError},
    signers::Signer,
};

use dkg_core::{
    primitives::{BundledJustification, BundledResponses, BundledShares},
    BoardPublisher,
};
use thiserror::Error;
use threshold_bls::group::Curve;

#[derive(Debug, Error)]
pub enum DKGContractError {
    #[error(transparent)]
    SerializationError(#[from] bincode::Error),
    #[error(transparent)]
    PublishingError(#[from] ContractError),
    #[error(transparent)]
    ProviderError(#[from] ProviderError),
}

impl<'a, C: Curve, P: JsonRpcClient, S: Signer> BoardPublisher<C> for DKG<'a, P, S> {
    type Error = DKGContractError;

    fn publish_shares(&mut self, shares: BundledShares<C>) -> Result<(), Self::Error> {
        let serialized = bincode::serialize(&shares)?;
        let fut = self.publish(serialized).send();
        let pending_tx = futures::executor::block_on(fut)?;
        let _tx_receipt = futures::executor::block_on(pending_tx)?;
        Ok(())
    }

    fn publish_responses(&mut self, responses: BundledResponses) -> Result<(), Self::Error> {
        let serialized = bincode::serialize(&responses)?;
        let fut = self.publish(serialized).send();
        let pending_tx = futures::executor::block_on(fut)?;
        let _tx_receipt = futures::executor::block_on(pending_tx)?;
        Ok(())
    }

    fn publish_justifications(
        &mut self,
        justifications: BundledJustification<C>,
    ) -> Result<(), Self::Error> {
        let serialized = bincode::serialize(&justifications)?;
        let fut = self.publish(serialized).send();
        let pending_tx = futures::executor::block_on(fut)?;
        let _tx_receipt = futures::executor::block_on(pending_tx)?;
        Ok(())
    }
}
