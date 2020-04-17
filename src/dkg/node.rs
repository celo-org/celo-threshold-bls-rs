use super::{
    board::BoardPublisher,
    primitives::{
        BundledResponses, BundledShares, DKGError, DKGOutput, DKGWaitingJustification,
        DKGWaitingResponse, DKGWaitingShare, Group, DKG,
    },
};
use crate::{group::Curve, Index};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    /// Node could not publish to the board
    #[error("Could not publish to board")]
    PublisherError,
    /// There was an internal error in the DKG
    #[error("DKG Error: {0}")]
    DKGError(#[from] DKGError),
}

/// A DKG Phase.
trait DKGPhase<C: Curve, B: BoardPublisher<C>, T> {
    /// The next DKG Phase
    type Next;

    /// Executes this DKG Phase and publishes the required result to the board.
    /// The `arg` is specific to each phase.
    fn run(self, board: &mut B, arg: T) -> Self::Next;
}

#[derive(Clone, Debug)]
struct Phase0<C: Curve> {
    inner: DKG<C>,
}

impl<C: Curve> Phase0<C> {
    fn new(private_key: C::Scalar, group: Group<C>) -> Result<Self, DKGError> {
        let dkg = DKG::new(private_key, group)?;
        Ok(Self { inner: dkg })
    }
}

#[derive(Clone, Debug)]
struct Phase1<C: Curve> {
    inner: DKGWaitingShare<C>,
}

#[derive(Clone, Debug)]
struct Phase2<C: Curve> {
    inner: DKGWaitingResponse<C>,
}

impl<C, B> DKGPhase<C, B, bool> for Phase0<C>
where
    C: Curve,
    B: BoardPublisher<C>,
{
    type Next = Result<Phase1<C>, NodeError>;

    fn run(self, board: &mut B, be_bad: bool) -> Self::Next {
        let (next, shares) = self.inner.shares();

        if !be_bad {
            board
                .publish_shares(shares)
                .map_err(|_| NodeError::PublisherError)?;
        }

        Ok(Phase1 { inner: next })
    }
}

impl<C, B> DKGPhase<C, B, &[BundledShares<C>]> for Phase1<C>
where
    C: Curve,
    B: BoardPublisher<C>,
{
    type Next = Result<Phase2<C>, NodeError>;

    fn run(self, board: &mut B, shares: &[BundledShares<C>]) -> Self::Next {
        let (next, bundle) = self.inner.process_shares(shares)?;

        if let Some(bundle) = bundle {
            board
                .publish_responses(bundle)
                .map_err(|_| NodeError::PublisherError)?;
        }

        Ok(Phase2 { inner: next, r })
    }
}

/// Phase2 can either be successful or require going to Phase 3.
#[derive(Clone, Debug)]
enum Phase2Result<C: Curve> {
    Output(DKGOutput<C>),
    GoToPhase3(DKGWaitingJustification<C>),
}

impl<C, B> DKGPhase<C, B, &[BundledResponses]> for Phase2<C>
where
    C: Curve,
    B: BoardPublisher<C>,
{
    type Next = Result<Phase2Result<C>, NodeError>;

    fn run(self, board: &mut B, responses: &[BundledResponses]) -> Self::Next {
        match self.inner.process_responses(responses) {
            Ok(output) => Ok(Phase2Result::Output(output)),
            Err((next, justifications)) => {
                // publish justifications if you have some
                // Nodes may just see that justifications are needed but they
                // don't have to create any, since no  complaint have been filed
                // against their deal.
                if let Some(justifications) = justifications {
                    board
                        .publish_justifications(justifications)
                        .map_err(|_| NodeError::PublisherError)?;
                }

                Ok(Phase2Result::GoToPhase3(next))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        // curve::zexe::PairingCurve,
        curve::bls12381::PairingCurve,
        dkg::{
            primitives::{Group, Node},
            test_helpers::InMemoryBoard,
        },
        group::{PairingCurve as PairingCurveTrait, Point},
        sig::{tblind::G2Scheme, Scheme},
    };

    #[test]
    fn dkg_e2e() {
        dkg_e2e_curve::<PairingCurve, G2Scheme<PairingCurve>>(10, 7)
    }

    fn dkg_e2e_curve<C, S>(n: usize, t: usize)
    where
        C: PairingCurveTrait,
        // The scheme uses Public keys on G2
        S: Scheme<Public = <C::G2Curve as Curve>::Point, Private = <C::G2Curve as Curve>::Scalar>,
        // The curve's points are over the same scalar as the scheme's
        <C::G2Curve as Curve>::Point: Point<S::Private>,
        // The signature scheme is a Point over the G2 Curve's scalar
        <S as Scheme>::Signature: Point<<C::G2Curve as Curve>::Scalar>,
    {
        let rng = &mut rand::thread_rng();

        let keypairs = (0..n).map(|_| S::keypair(rng)).collect::<Vec<_>>();

        let nodes = keypairs
            .iter()
            .enumerate()
            .map(|(i, (_, public))| Node::<C::G2Curve>::new(i as Index, public.clone()))
            .collect::<Vec<_>>();

        // This is setup phase during which publickeys and indexes must be exchanged
        // across participants
        let group = Group::new(nodes, t).unwrap();

        // Create the Phase 0 for each participant
        let phase0s = keypairs
            .iter()
            .map(|(private, _)| Phase0::new(private.clone(), group.clone()).unwrap())
            .collect::<Vec<_>>();

        // Create the board
        let mut board = InMemoryBoard::<C::G2Curve>::new();

        // Phase 1: Publishes shares, all nodes are honest
        let phase1s = phase0s
            .into_iter()
            .map(|phase0| phase0.run(&mut board, false).unwrap())
            .collect::<Vec<_>>();

        // get the full vector
        let shares = board.shares.clone();

        // Phase2:
        let phase2s = phase1s
            .into_iter()
            .map(|phase1| phase1.run(&mut board, &shares).unwrap())
            .collect::<Vec<_>>();

        let responses = board.responses.clone();

        let results = phase2s
            .into_iter()
            .map(|phase2| phase2.run(&mut board, &responses).unwrap())
            .collect::<Vec<_>>();

        // The distributed public key must be the same
        let dist_pubkeys = results
            .into_iter()
            .map(|res| match res {
                Phase2Result::Output(out) => return out.public,
                _ => unreachable!("should not get here"),
            })
            .collect::<Vec<_>>();
        assert!(is_all_same(&dist_pubkeys));
    }

    fn is_all_same<T: PartialEq>(arr: &[T]) -> bool {
        if arr.is_empty() {
            return true;
        }
        let first = &arr[0];
        arr.iter().all(|item| item == first)
    }
}
