use super::{
    board::BoardPublisher,
    primitives::{
        BundledResponses, BundledShares, DKGError, DKGOutput, DKGWaitingJustification,
        DKGWaitingResponse, DKGWaitingShare, Group, DKG,
    },
};
use crate::group::Curve;
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
pub trait DKGPhase<C: Curve, B: BoardPublisher<C>, T> {
    /// The next DKG Phase
    type Next;

    /// Executes this DKG Phase and publishes the required result to the board.
    /// The `arg` is specific to each phase.
    fn run(self, board: &mut B, arg: T) -> Self::Next;
}

#[derive(Clone, Debug)]
pub struct Phase0<C: Curve> {
    inner: DKG<C>,
}

impl<C: Curve> Phase0<C> {
    pub fn new(private_key: C::Scalar, group: Group<C>) -> Result<Self, DKGError> {
        let dkg = DKG::new(private_key, group)?;
        Ok(Self { inner: dkg })
    }
}

#[derive(Clone, Debug)]
pub struct Phase1<C: Curve> {
    inner: DKGWaitingShare<C>,
}

#[derive(Clone, Debug)]
pub struct Phase2<C: Curve> {
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

        Ok(Phase2 { inner: next })
    }
}

/// Phase2 can either be successful or require going to Phase 3.
#[derive(Clone, Debug)]
pub enum Phase2Result<C: Curve> {
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
        curve::bls12381::{self, PairingCurve as BLS12_381},
        curve::zexe::{self as bls12_377, PairingCurve as BLS12_377},
        dkg::{
            primitives::{Group, Node},
            test_helpers::InMemoryBoard,
        },
        group::{Element, Encodable, Point},
        sig::{
            tblind::{G1Scheme, G2Scheme},
            Blinder, Scheme, ThresholdScheme,
        },
        Index,
    };

    #[test]
    fn dkg_sign_e2e() {
        let (t, n) = (2, 3);
        dkg_sign_e2e_curve::<bls12381::Curve, G1Scheme<BLS12_381>>(n, t);
        dkg_sign_e2e_curve::<bls12381::G2Curve, G2Scheme<BLS12_381>>(n, t);

        dkg_sign_e2e_curve::<bls12_377::G1Curve, G1Scheme<BLS12_377>>(n, t);
        dkg_sign_e2e_curve::<bls12_377::G2Curve, G2Scheme<BLS12_377>>(n, t);
    }

    fn dkg_sign_e2e_curve<C, S>(n: usize, t: usize)
    where
        C: Curve,
        // We need to bind the Curve's Point and Scalars to the Scheme
        S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>
            + Blinder
            + ThresholdScheme,
        <C as Curve>::Point: Point<S::Private>,
        <S as Scheme>::Signature: Point<<C as Curve>::Scalar>,
    {
        let msg = rand::random::<[u8; 32]>().to_vec();

        // executes the DKG state machine and ensures that the keys are generated correctly
        let outputs = run_dkg::<C, S>(n, t);

        // blinds the message
        let (token, blinded_msg) = S::blind(&msg[..], &mut rand::thread_rng());

        // generates a partial sig with each share from the dkg
        let partial_sigs = outputs
            .iter()
            .map(|output| S::partial_sign(&output.share, &blinded_msg[..]).unwrap())
            .collect::<Vec<_>>();

        // aggregates them
        let blinded_sig = S::aggregate(t, &partial_sigs).unwrap();

        // the user unblinds it
        let unblinded_sig = S::unblind(&token, &blinded_sig).unwrap();

        // get the public key (we have already checked that all outputs' pubkeys are the same)
        let pubkey = outputs[0].public.public_key();

        // verify the threshold signature _against the hash of the message_
        let mut msg_point = <S as Scheme>::Signature::new();
        msg_point.map(&msg).unwrap();
        let msg = msg_point.marshal();
        S::verify(&pubkey, &msg, &unblinded_sig).unwrap();
    }

    fn run_dkg<C, S>(n: usize, t: usize) -> Vec<DKGOutput<C>>
    where
        C: Curve,
        // We need to bind the Curve's Point and Scalars to the Scheme
        S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
        <C as Curve>::Point: Point<S::Private>,
        <S as Scheme>::Signature: Point<<C as Curve>::Scalar>,
    {
        let rng = &mut rand::thread_rng();

        let (mut board, phase0s) = setup::<C, S, _>(n, t, rng);

        // Phase 1: Publishes shares, all nodes are honest
        let phase1s = phase0s
            .into_iter()
            .map(|phase0| phase0.run(&mut board, false).unwrap())
            .collect::<Vec<_>>();

        // Get the shares from the board
        let shares = board.shares.clone();

        // Phase2:
        let phase2s = phase1s
            .into_iter()
            .map(|phase1| phase1.run(&mut board, &shares).unwrap())
            .collect::<Vec<_>>();

        // Get the responses from the board
        let responses = board.responses.clone();

        let results = phase2s
            .into_iter()
            .map(|phase2| phase2.run(&mut board, &responses).unwrap())
            .collect::<Vec<_>>();

        // The distributed public key must be the same
        let outputs = results
            .into_iter()
            .map(|res| match res {
                Phase2Result::Output(out) => out,
                _ => unreachable!("should not get here"),
            })
            .collect::<Vec<_>>();
        assert!(is_all_same(outputs.iter().map(|output| &output.public)));

        outputs
    }

    fn setup<C, S, R: rand::RngCore>(
        n: usize,
        t: usize,
        rng: &mut R,
    ) -> (InMemoryBoard<C>, Vec<Phase0<C>>)
    where
        C: Curve,
        // We need to bind the Curve's Point and Scalars to the Scheme
        S: Scheme<Public = <C as Curve>::Point, Private = <C as Curve>::Scalar>,
        <C as Curve>::Point: Point<S::Private>,
        <S as Scheme>::Signature: Point<<C as Curve>::Scalar>,
    {
        // generate a keypair per participant
        let keypairs = (0..n).map(|_| S::keypair(rng)).collect::<Vec<_>>();

        let nodes = keypairs
            .iter()
            .enumerate()
            .map(|(i, (_, public))| Node::<C>::new(i as Index, public.clone()))
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
        let board = InMemoryBoard::<C>::new();

        (board, phase0s)
    }

    fn is_all_same<T: PartialEq>(mut arr: impl Iterator<Item = T>) -> bool {
        let first = arr.next().unwrap();
        arr.all(|item| item == first)
    }
}
