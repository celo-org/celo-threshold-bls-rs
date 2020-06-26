//! Implements the Distributed Key Generation protocol from
//! [Pedersen](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf).
//! The protocol runs at minimum in two phases and at most in three phases.
use super::common::*;
use crate::primitives::{
    group::Group,
    phases::{Phase0, Phase1, Phase2, Phase3},
    status::StatusMatrix,
    types::*,
    DKGError, DKGResult,
};

use threshold_bls::{
    group::{Curve, Element},
    poly::{Idx, Poly, PrivatePoly, PublicPoly},
    sig::Share,
};

use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{cell::RefCell, collections::HashMap, fmt::Debug};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
struct DKGInfo<C: Curve> {
    private_key: C::Scalar,
    public_key: C::Point,
    index: Idx,
    group: Group<C>,
    secret: Poly<C::Scalar>,
    public: Poly<C::Point>,
}

impl<C: Curve> DKGInfo<C> {
    /// Returns the number of nodes participating in the group for this DKG
    fn n(&self) -> usize {
        self.group.len()
    }

    /// Returns the threshold of the group for this DKG
    fn thr(&self) -> usize {
        self.group.threshold
    }
}

/// DKG is the struct containing the logic to run the Distributed Key Generation
/// protocol from [Pedersen](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf).
///
/// The protocol runs at minimum in two phases and at most in three phases as
/// described in the module documentation.
///
/// Each transition to a new phase is consuming the DKG state (struct) to produce
/// a new state that only accepts to transition to the next phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKG<C: Curve> {
    /// Metadata about the DKG
    info: DKGInfo<C>,
}

impl<C: Curve> DKG<C> {
    /// Creates a new DKG instance from the provided private key and group.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub fn new(private_key: C::Scalar, group: Group<C>) -> Result<DKG<C>, DKGError> {
        use rand::prelude::*;
        Self::new_rand(private_key, group, &mut thread_rng())
    }

    /// Creates a new DKG instance from the provided private key, group and RNG.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub fn new_rand<R: RngCore>(
        private_key: C::Scalar,
        group: Group<C>,
        rng: &mut R,
    ) -> Result<DKG<C>, DKGError> {
        // get the public key
        let mut public_key = C::Point::one();
        public_key.mul(&private_key);

        // check if the public key is part of the group
        let index = group
            .index(&public_key)
            .ok_or_else(|| DKGError::PublicKeyNotFound)?;

        // Generate a secret polynomial and commit to it
        let secret = PrivatePoly::<C>::new_from(group.threshold - 1, rng);
        let public = secret.commit::<C::Point>();

        let info = DKGInfo {
            private_key,
            public_key,
            index,
            group,
            secret,
            public,
        };

        Ok(DKG { info })
    }
}

impl<C: Curve> Phase0<C> for DKG<C> {
    type Next = DKGWaitingShare<C>;
    /// Evaluates the secret polynomial at the index of each DKG participant and encrypts
    /// the result with the corresponding public key. Returns the bundled encrypted shares
    /// as well as the next phase of the DKG.
    fn encrypt_shares<R: RngCore>(
        self,
        rng: &mut R,
    ) -> DKGResult<(DKGWaitingShare<C>, Option<BundledShares<C>>)> {
        let bundle = create_share_bundle(
            self.info.index,
            &self.info.secret,
            &self.info.public,
            &self.info.group,
            rng,
        )?;
        let dw = DKGWaitingShare { info: self.info };
        Ok((dw, Some(bundle)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// DKG Stage which waits to receive the shares from the previous phase's participants
/// as input. After processing the shares, if there were any complaints it will generate
/// a bundle of responses for the next phase.
pub struct DKGWaitingShare<C: Curve> {
    /// Metadata about the DKG
    info: DKGInfo<C>,
}

impl<C: Curve> Phase1<C> for DKGWaitingShare<C> {
    type Next = DKGWaitingResponse<C>;
    #[allow(unused_assignments)]
    /// Tries to decrypt the provided shares and calculate the secret key and the
    /// threshold public key. If `publish_all` is set to true then the returned
    /// responses will include both complaints and successful statuses. Consider setting
    /// it to false when communication complexity is high.
    ///
    /// A complaint is returned in the following cases:
    /// - invalid dealer index
    /// - absentee shares for us
    /// - invalid encryption
    /// - invalid length of public polynomial
    /// - invalid share w.r.t. public polynomial
    fn process_shares(
        self,
        bundles: &[BundledShares<C>],
        mut publish_all: bool,
    ) -> DKGResult<(DKGWaitingResponse<C>, Option<BundledResponses>)> {
        publish_all = false;
        let thr = self.info.thr();
        let my_idx = self.info.index;
        let (shares, publics, statuses) = process_shares_get_all(
            &self.info.group,
            &self.info.group,
            Some(my_idx),
            my_idx,
            &self.info.private_key,
            bundles,
        )?;

        // we check with `thr - 1` because we already have our shares
        if shares.len() < thr - 1 {
            // that means the threat model is not respected since there should
            // be at least a threshold of honest shares
            return Err(DKGError::NotEnoughValidShares(shares.len(), thr));
        }

        // The user's secret share is the sum of all received shares (remember:
        // each share is an evaluation of a participant's private polynomial at
        // our index)
        let mut fshare = self.info.secret.eval(self.info.index).value;
        // The public key polynomial is the sum of all shared polynomials
        let mut fpub = self.info.public.clone();
        shares.iter().for_each(|(&dealer_idx, share)| {
            fpub.add(&publics.get(&dealer_idx).unwrap());
            fshare.add(&share);
        });
        let bundle = compute_bundle_response(my_idx, &statuses, publish_all);
        let new_dkg = DKGWaitingResponse::new(self.info, fshare, fpub, statuses, publics);

        Ok((new_dkg, bundle))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// DKG Stage which waits to receive the responses from the previous phase's participants
/// as input. The responses will be processed and justifications may be generated as a byproduct
/// if there are complaints.
pub struct DKGWaitingResponse<C: Curve> {
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    statuses: StatusMatrix,
    publics: PublicInfo<C>,
}

impl<C: Curve> DKGWaitingResponse<C> {
    fn new(
        info: DKGInfo<C>,
        dist_share: C::Scalar,
        dist_pub: PublicPoly<C>,
        statuses: StatusMatrix,
        publics: PublicInfo<C>,
    ) -> Self {
        Self {
            info,
            dist_share,
            dist_pub,
            statuses,
            publics,
        }
    }
}

impl<C: Curve> Phase2<C> for DKGWaitingResponse<C> {
    type Next = DKGWaitingJustification<C>;
    #[allow(clippy::type_complexity)]
    /// Checks if the responses when applied to the status matrix result in a
    /// matrix with only `Success` elements. If so, the protocol terminates.
    ///
    /// If there are complaints in the Status matrix, then it will return an
    /// error with the justifications required for Phase 3 of the DKG.
    fn process_responses(
        self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, DKGResult<(Self::Next, Option<BundledJustification<C>>)>> {
        let info = self.info;
        let mut statuses = self.statuses;
        set_statuses(
            info.index,
            &info.group,
            &info.group,
            &mut statuses,
            responses,
        );

        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let justifications_required = info.group.nodes.iter().any(|n| !statuses.all_true(n.id()));

        if justifications_required {
            let bundled_justifications =
                get_justification(info.index, &info.secret, &info.public, &statuses);
            let dkg = DKGWaitingJustification {
                info,
                dist_share: self.dist_share,
                dist_pub: self.dist_pub,
                statuses: RefCell::new(statuses),
                publics: self.publics,
            };

            return Err(Ok((dkg, bundled_justifications)));
        }

        // bingo ! Returns the final share now and stop the protocol
        let share = Share {
            index: info.index,
            private: self.dist_share,
        };

        Ok(DKGOutput {
            // everybody is qualified in this case since there is no
            // complaint at all
            qual: info.group,
            public: self.dist_pub,
            share,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// DKG Stage which waits to receive the justifications from the previous phase's participants
/// as input to produce either the final DKG Output, or an error.
pub struct DKGWaitingJustification<C: Curve> {
    // TODO: transform that into one info variable that gets default value for
    // missing parts depending in the round of the protocol.
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    // guaranteed to be of the right size (n)
    statuses: RefCell<StatusMatrix>,
    publics: HashMap<Idx, PublicPoly<C>>,
}

impl<C> Phase3<C> for DKGWaitingJustification<C>
where
    C: Curve,
{
    /// Accept a justification if the following conditions are true:
    /// - bundle's dealer index is in range
    /// - a justification was required for the given share (no-op)
    /// - share corresponds to public polynomial received in the bundled shares during
    /// first period.
    /// Return an output if `len(qual) > thr`
    fn process_justifications(
        self,
        justifs: &[BundledJustification<C>],
    ) -> Result<DKGOutput<C>, DKGError> {
        // Calculate the share and public polynomial from the provided justifications
        // (they will later be added to our existing share and public polynomial)
        let mut add_share = C::Scalar::zero();
        let mut add_public = PublicPoly::<C>::zero();
        let valid_shares = internal_process_justifications(
            self.info.index,
            &self.info.group,
            &mut self.statuses.borrow_mut(),
            &self.publics,
            justifs,
        );

        for (idx, share) in &valid_shares {
            add_share.add(&share);
            // unwrap since internal_process_justi. gauarantees each share comes
            // from a public polynomial we've seen in the first round.
            add_public.add(&self.publics.get(idx).unwrap());
        }
        // QUAL is the set of all entries in the matrix where all bits are set
        let statuses = self.statuses.borrow();
        let qual_indices = (0..self.info.n())
            .filter(|&dealer| statuses.all_true(dealer as Idx))
            .collect::<Vec<_>>();

        let thr = self.info.group.threshold;
        if qual_indices.len() < thr {
            // too many unanswered justifications, DKG abort !
            return Err(DKGError::NotEnoughJustifications(qual_indices.len(), thr));
        }

        // create a group out of the qualifying nodes
        let qual_nodes = self
            .info
            .group
            .nodes
            .into_iter()
            .filter(|n| qual_indices.contains(&(n.id() as usize)))
            .collect();
        let group = Group::<C>::new(qual_nodes, thr)?;

        // add all good shares and public poly together
        add_share.add(&self.dist_share);
        add_public.add(&self.dist_pub);
        let ds = Share {
            index: self.info.index,
            private: add_share,
        };

        Ok(DKGOutput {
            qual: group,
            public: add_public,
            share: ds,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::primitives::{
        common::tests::{check2, full_dkg, id_out, id_resp, invalid2, invalid_shares, setup_group},
        default_threshold,
    };
    use std::fmt::Debug;
    use threshold_bls::curve::bls12381::{Curve as BCurve, G1};

    use serde::{de::DeserializeOwned, Serialize};
    use static_assertions::assert_impl_all;

    assert_impl_all!(Group<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(DKGInfo<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(DKG<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(EncryptedShare<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(BundledShares<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(DKGOutput<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(BundledJustification<BCurve>: Serialize, DeserializeOwned, Clone, Debug);

    fn setup_dkg<C: Curve>(n: usize) -> Vec<DKG<C>> {
        let (privs, group) = setup_group::<C>(n, default_threshold(n));
        privs
            .into_iter()
            .map(|p| DKG::new(p, group.clone()).unwrap())
            .collect::<Vec<_>>()
    }

    #[test]
    fn group_index() {
        let n = 6;
        let (privs, group) = setup_group::<BCurve>(n, default_threshold(n));
        for (i, private) in privs.iter().enumerate() {
            let mut public = G1::one();
            public.mul(&private);
            let idx = group.index(&public).expect("should find public key");
            assert_eq!(idx, i as Idx);
        }
    }

    #[test]
    fn test_full_dkg() {
        let n = 5;
        let thr = default_threshold(n);
        full_dkg(thr, setup_dkg::<BCurve>(n));
    }

    #[test]
    fn test_invalid_shares_dkg() {
        let n = 5;
        let thr = default_threshold(n);
        invalid_shares(
            thr,
            setup_dkg::<BCurve>(n),
            invalid2,
            id_resp,
            check2,
            id_out,
        )
        .unwrap();
    }
}
