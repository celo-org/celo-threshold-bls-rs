//! Implements the resharing scheme from [Desmedt et al.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.55.2968&rep=rep1&type=pdf)).
//! The protoocol has the same phases as the JF-DKG module but requires additional checks
//! to verify the resharing is performed correctly. The resharing scheme runs
//! between two potentially distinct groups: the dealers (nodes that already
//! have a share, that ran a DKG previously) and the share holders (nodes that
//! receives a refreshed share of the same secret).
use super::common::*;
use crate::primitives::{
    group::Group,
    phases::{Phase0, Phase1, Phase2, Phase3},
    status::{Status, StatusMatrix},
    types::*,
    DKGError, DKGResult,
};

use threshold_bls::{
    group::{Curve, Element},
    poly::{Eval, Idx, Poly, PrivatePoly, PublicPoly},
    sig::Share,
};

use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{cell::RefCell, fmt::Debug};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
struct ReshareInfo<C: Curve> {
    private_key: C::Scalar,
    public_key: C::Point,
    // our previous index in the group - it can be none if we are a new member
    prev_index: Option<Idx>,
    // previous group on which to reshare
    prev_group: Group<C>,
    // previous group distributed public polynomial
    prev_public: Poly<C::Point>,
    // secret and public polynomial of a dealer
    secret: Option<Poly<C::Scalar>>,
    public: Option<Poly<C::Point>>,

    // our new index in the group - it can be none if we are a leaving member
    new_index: Option<Idx>,
    // new group that is receiving the refreshed shares
    new_group: Group<C>,
}

impl<C: Curve> ReshareInfo<C> {
    fn is_dealer(&self) -> bool {
        self.prev_index.is_some()
    }
    fn is_share_holder(&self) -> bool {
        self.new_index.is_some()
    }
}

/// RDKG is the struct containing the logic to run the resharing scheme from
/// Desmedt et al.
/// ([paper](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.55.2968&rep=rep1&type=pdf)).
/// The protoocol has the same phases of the DKG but requires additional checks
/// to verify the resharing is performed correctly. The resharing scheme runs
/// between two potentially distinct groups: the dealers (nodes that already
/// have a share, that ran a DKG previously) and the share holders (nodes that
/// receives a refreshed share of the same secret).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct RDKG<C: Curve> {
    info: ReshareInfo<C>,
}

impl<C: Curve> RDKG<C> {
    pub fn new_from_share(
        private_key: C::Scalar,
        curr_share: DKGOutput<C>,
        new_group: Group<C>,
    ) -> Result<RDKG<C>, DKGError> {
        use rand::prelude::*;
        Self::new_from_share_rng(private_key, curr_share, new_group, &mut thread_rng())
    }

    pub fn new_from_share_rng<R: RngCore>(
        private_key: C::Scalar,
        curr_share: DKGOutput<C>,
        new_group: Group<C>,
        rng: &mut R,
    ) -> Result<RDKG<C>, DKGError> {
        let oldi = Some(curr_share.share.index);
        let prev_group = curr_share.qual;
        let prev_public = curr_share.public;
        // generate a secret polynomial with the share being the free
        // coefficient
        let mut secret = PrivatePoly::<C>::new_from(new_group.threshold - 1, rng);
        secret.set(0, curr_share.share.private);
        let public = secret.commit::<C::Point>();
        let mut pubkey = C::point();
        pubkey.mul(&private_key);
        let new_idx = new_group.index(&pubkey);
        let info = ReshareInfo {
            private_key,
            public_key: pubkey,
            prev_index: oldi,
            prev_group,
            prev_public,
            secret: Some(secret),
            public: Some(public),
            new_index: new_idx,
            new_group,
        };
        Ok(RDKG { info })
    }

    pub fn new_member(
        private_key: C::Scalar,
        curr_group: Group<C>,
        curr_public: PublicPoly<C>,
        new_group: Group<C>,
    ) -> Result<RDKG<C>, DKGError> {
        let mut pubkey = C::point();
        pubkey.mul(&private_key);
        let new_idx = new_group.index(&pubkey);
        let info = ReshareInfo {
            private_key,
            public_key: pubkey,
            prev_index: None,
            prev_group: curr_group,
            prev_public: curr_public,
            secret: None,
            public: None,
            new_index: new_idx,
            new_group,
        };
        Ok(RDKG { info })
    }
}

impl<C: Curve> Phase0<C> for RDKG<C> {
    type Next = RDKGWaitingShare<C>;
    fn encrypt_shares<R: RngCore>(
        self,
        rng: &mut R,
    ) -> DKGResult<(RDKGWaitingShare<C>, Option<BundledShares<C>>)> {
        if !self.info.is_dealer() {
            return Ok((RDKGWaitingShare { info: self.info }, None));
        }
        let info = self.info;
        let public = info.public.unwrap();
        let secret = info.secret.unwrap();
        let bundle = create_share_bundle(
            info.prev_index.unwrap(),
            &secret,
            &public,
            &info.new_group,
            rng,
        )?;
        let dw = RDKGWaitingShare {
            info: ReshareInfo {
                public: Some(public),
                secret: Some(secret),
                ..info
            },
        };
        Ok((dw, Some(bundle)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// Resharing stage which waits to receive the shares from the previous phase's
/// participants as input. After processing the share, if there were any
/// complaints, it will generate a bundle of responses for the next phase.
pub struct RDKGWaitingShare<C: Curve> {
    info: ReshareInfo<C>,
}

impl<C: Curve> Phase1<C> for RDKGWaitingShare<C> {
    type Next = RDKGWaitingResponse<C>;
    #[allow(unused_assignments)]
    fn process_shares(
        self,
        bundles: &[BundledShares<C>],
        mut publish_all: bool,
    ) -> DKGResult<(RDKGWaitingResponse<C>, Option<BundledResponses>)> {
        publish_all = false;
        if !self.info.is_share_holder() {
            return Ok((
                RDKGWaitingResponse {
                    statuses: StatusMatrix::new(
                        self.info.prev_group.len(),
                        self.info.new_group.len(),
                        Status::Success,
                    ),
                    info: self.info,
                    shares: ShareInfo::<C>::new(),
                    publics: PublicInfo::<C>::new(),
                },
                None,
            ));
        }

        let my_idx = self.info.new_index.unwrap();
        let (mut shares, mut publics, mut statuses) = process_shares_get_all(
            &self.info.prev_group,
            &self.info.new_group,
            self.info.prev_index,
            my_idx,
            &self.info.private_key,
            bundles,
        )?;

        // set the status to true for any dealer that is also a share holder
        // we compare the public keys from the previous group to the new group
        // to know if that is the case
        for prev in self.info.prev_group.nodes.iter() {
            if let Some(nidx) = self.info.new_group.index(prev.key()) {
                statuses.set(prev.id(), nidx, Status::Success);
            }
        }

        println!(
            "{} - PROCESS SHARES: {:?} -> {:?} - {}",
            self.info.new_index.as_ref().unwrap(),
            bundles.iter().map(|b| b.dealer_idx).collect::<Vec<Idx>>(),
            shares.iter().map(|(&k, _)| k).collect::<Vec<Idx>>(),
            statuses,
        );

        bundles
            .iter()
            // this bundle was invalid for some reason
            .filter(|b| publics.contains_key(&b.dealer_idx))
            // only keep the ones that don't respect the rules to remove them
            // from the list of valid shares and put their status to complaint
            .filter(|b| {
                !check_public_resharing::<C>(b.dealer_idx, &b.public, &self.info.prev_public)
            })
            .for_each(|b| {
                println!("REMOVE BUNDLE: {}", b.dealer_idx);
                shares.remove(&b.dealer_idx);
                for n in &self.info.new_group.nodes {
                    statuses.set(b.dealer_idx, n.id(), Status::Complaint);
                }
            });

        let mut info = self.info;
        if info.is_dealer() {
            let public = info.public.take().unwrap();
            let secret = info.secret.take().unwrap();
            // we register our own share and publics into the mix
            let didx = info.prev_index.unwrap();
            shares.insert(didx, secret.eval(didx).value);
            publics.insert(didx, public.clone());
            // we treat our own share as valid!
            statuses.set(didx, my_idx, Status::Success);
            info.public = Some(public);
            info.secret = Some(secret);
        }

        // we need at least a threshold of dealers to share their share to be
        // able to reconstruct a share of the same distributed private key.
        if shares.len() < info.prev_group.threshold {
            return Err(DKGError::NotEnoughValidShares(
                shares.len(),
                info.prev_group.threshold,
            ));
        }

        let bundle = compute_bundle_response(my_idx, &statuses, publish_all);
        let new_dkg = RDKGWaitingResponse {
            info,
            shares,
            publics,
            statuses,
        };
        Ok((new_dkg, bundle))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct RDKGWaitingResponse<C: Curve> {
    info: ReshareInfo<C>,
    shares: ShareInfo<C>,
    publics: PublicInfo<C>,
    statuses: StatusMatrix,
}

impl<C: Curve> Phase2<C> for RDKGWaitingResponse<C> {
    type Next = RDKGWaitingJustification<C>;

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
        if !self.info.is_share_holder() {
            // we just silently pass
            let dkg = RDKGWaitingJustification {
                info: self.info,
                shares: self.shares,
                statuses: RefCell::new(self.statuses),
                publics: self.publics,
            };
            return Err(Ok((dkg, None)));
        }

        let info = self.info;
        let mut statuses = self.statuses;
        set_statuses(
            info.new_index.unwrap(),
            &info.prev_group,
            &info.new_group,
            &mut statuses,
            responses,
        );

        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let justifications_required = info
            .prev_group
            .nodes
            .iter()
            .any(|n| !statuses.all_true(n.id()));

        if justifications_required {
            // we can only create justifications if we are a dealer
            let bundled_justifications = if info.is_dealer() {
                let public = info.public.as_ref().unwrap();
                let secret = info.secret.as_ref().unwrap();
                get_justification(info.prev_index.unwrap(), secret, public, &statuses)
            } else {
                None
            };
            let dkg = RDKGWaitingJustification {
                info,
                shares: self.shares,
                statuses: RefCell::new(statuses),
                publics: self.publics,
            };
            return Err(Ok((dkg, bundled_justifications)));
        }
        // in case of error here, the protocol must be aborted
        compute_resharing_output(info, self.shares, self.publics, RefCell::new(statuses))
            .map_err(Err)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct RDKGWaitingJustification<C: Curve> {
    info: ReshareInfo<C>,
    shares: ShareInfo<C>,
    publics: PublicInfo<C>,
    // guaranteed to be of the right size (n)
    statuses: RefCell<StatusMatrix>,
}

impl<C> Phase3<C> for RDKGWaitingJustification<C>
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
    ) -> DKGResult<DKGOutput<C>> {
        if !self.info.is_share_holder() {
            return Err(DKGError::NotShareHolder);
        }
        let mut valid_shares = internal_process_justifications(
            self.info.new_index.unwrap(),
            &self.info.prev_group,
            &mut self.statuses.borrow_mut(),
            &self.publics,
            justifs,
        );

        let info = self.info;
        let publics = self.publics;
        let shares = self.shares;
        let statuses = self.statuses;
        justifs
            .iter()
            // this bundle was already invalid for some reason
            .filter(|b| publics.contains_key(&b.dealer_idx))
            // only keep the ones that don't respect the rules to remove them
            // from the list of valid shares and put their status to complaint
            .filter(|b| {
                !check_public_resharing::<C>(
                    b.dealer_idx,
                    // take the public polynomial we received in the first step
                    publics.get(&b.dealer_idx).unwrap(),
                    &info.prev_public,
                )
            })
            .for_each(|b| {
                // we remove the shares coming from invalid justification
                valid_shares.remove(&b.dealer_idx);
                for n in &info.new_group.nodes {
                    statuses
                        .borrow_mut()
                        .set(b.dealer_idx, n.id(), Status::Complaint);
                }
            });

        println!(" BEFORE JUSTIFICATION OUTPUT: {}", statuses.borrow());
        compute_resharing_output(
            info,
            valid_shares.into_iter().chain(shares).collect(),
            publics,
            statuses,
        )
    }
}

fn compute_resharing_output<C: Curve>(
    info: ReshareInfo<C>,
    shares: ShareInfo<C>,
    publics: PublicInfo<C>,
    statuses: RefCell<StatusMatrix>,
) -> DKGResult<DKGOutput<C>> {
    // to compute the final share, we interpolate all the valid shares received
    let mut shares_eval: Vec<Eval<C::Scalar>> = shares
        .into_iter()
        .map(|(idx, sh)| Eval {
            value: sh,
            index: idx,
        })
        .collect();

    // only take the first t shares sorted
    shares_eval.sort_by(|a, b| a.index.cmp(&b.index));
    let shares_indexes = shares_eval.iter().map(|e| e.index).collect::<Vec<Idx>>();
    let shortened_evals = shares_eval
        .into_iter()
        .take(info.prev_group.threshold)
        .collect::<Vec<Eval<C::Scalar>>>();

    //println!(" --- recovering on shares: {:?}", shortened_evals);
    let recovered_share = Poly::recover(info.prev_group.threshold, shortened_evals)
        .map_err(DKGError::InvalidRecovery)?;
    // recover public polynomial by interpolating coefficient-wise all
    // polynomials. the new public polynomial have "newT"
    // coefficients
    let recovered_public: PublicPoly<C> = (0..info.new_group.threshold)
        .map(|cidx| {
            // interpolate the cidx coefficient of the final public polynomial
            let to_recover = shares_indexes
                .iter()
                .map(|sh_idx| {
                    match publics.get(sh_idx) {
                        Some(poly) => Eval {
                            // value is the cidx coefficient of that dealer's public
                            // poly
                            value: poly.get(cidx as Idx),
                            // the index is the index from the dealer
                            index: *sh_idx,
                        },
                        None => panic!("BUG: public polynomial evaluating failed"),
                    }
                })
                .collect::<Vec<_>>();

            // recover the cidx coefficient of the final public polynomial
            Poly::recover(info.prev_group.threshold, to_recover).map_err(DKGError::InvalidRecovery)
        })
        .collect::<Result<Vec<C::Point>, DKGError>>()?
        .into();
    // To compute the QUAL in the resharing case, we take each new nodes whose
    // column in the status matrix contains true for all valid dealers.
    let qual = info
        .new_group
        .nodes
        .into_iter()
        .filter(|node| {
            shares_indexes
                .iter()
                .all(|&sidx| statuses.borrow().get(sidx, node.id()).is_success())
        })
        .collect::<Vec<_>>();

    let qual_group = Group::<C>::new(qual, info.new_group.threshold)?;
    Ok(DKGOutput {
        qual: qual_group,
        public: recovered_public,
        share: Share {
            index: info.new_index.unwrap(),
            private: recovered_share,
        },
    })
}

// we verify that the public polynomial is created with the public
// share of the dealer,i.e. it's actually a resharing
// if it returns false, we must set the dealer's shares as being complaint, all
// of them since he is not respecting the protocol
fn check_public_resharing<C: Curve>(
    dealer_idx: Idx,
    deal_poly: &PublicPoly<C>,
    group_poly: &PublicPoly<C>,
) -> bool {
    // evaluation of the public key the dealer gives us which should be
    // the commitment of its current share
    let given = deal_poly.public_key();
    // computing the current share commitment of the dealer
    let expected = &group_poly.eval(dealer_idx).value;
    expected == given
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{
        common::tests::{check2, full_dkg, id_out, id_resp, invalid2, invalid_shares, setup_group},
        default_threshold,
    };
    use threshold_bls::{
        curve::bls12377::{G1Curve as BCurve, Scalar, G1},
        ecies,
    };

    use rand::prelude::*;

    fn setup_reshare<C: Curve>(
        old_n: usize,
        old_thr: usize,
        new_n: usize,
        new_thr: usize,
    ) -> (Vec<RDKG<C>>, PublicPoly<C>) {
        let (prev_privs, prev_group) = setup_group::<C>(old_n, old_thr);
        // simulate shares
        let private_poly = Poly::<C::Scalar>::new_from(prev_group.threshold - 1, &mut thread_rng());
        let public_poly = private_poly.commit::<C::Point>();

        // assume strictly greater group
        let new_priv = if new_n > 0 {
            let (npriv, _) = setup_group::<C>(new_n - old_n, new_thr);
            Some(npriv)
        } else {
            None
        };

        // create the new group
        let mut new_group = if new_n > 0 {
            Group::from(
                prev_privs
                    .iter()
                    .chain(new_priv.as_ref().unwrap().iter())
                    .map(|pr| {
                        let mut public = C::Point::one();
                        public.mul(pr);
                        public
                    })
                    .collect::<Vec<C::Point>>(),
            )
        } else {
            prev_group.clone()
        };
        if new_n > 0 {
            new_group.threshold = new_thr;
        } else {
            // we use the same threshold as "fake" group in this case
            new_group.threshold = old_thr;
        }

        let mut dkgs = prev_privs
            .into_iter()
            .zip(prev_group.nodes.iter().map(|n| private_poly.eval(n.id())))
            .map(|(p, sh)| {
                let out = DKGOutput {
                    share: Share {
                        index: sh.index,
                        private: sh.value,
                    },
                    public: public_poly.clone(),
                    qual: prev_group.clone(),
                };
                RDKG::new_from_share(p, out, new_group.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        if new_n > 0 {
            dkgs = dkgs
                .into_iter()
                .chain(new_priv.unwrap().into_iter().map(|pr| {
                    RDKG::new_member(
                        pr,
                        prev_group.clone(),
                        public_poly.clone(),
                        new_group.clone(),
                    )
                    .unwrap()
                }))
                .collect::<Vec<_>>();
        }
        (dkgs, public_poly)
    }

    #[test]
    fn test_invalid_shares_reshare() {
        let n = 5;
        let thr = default_threshold(n);
        println!(" -------- FIRST SCENARIO ---------- ");
        // scenario 1.
        // just change two shares and give it invalid things
        let (dkgs, public) = setup_reshare::<BCurve>(n, thr, 0, 0);
        let reshared = invalid_shares(thr, dkgs, invalid2, id_resp, check2, id_out).unwrap();
        // test that it gives the same public key
        assert_eq!(public.public_key(), reshared.public_key());

        println!(" -------- SECOND SCENARIO ---------- ");
        // SCENARIO 2.
        // change the public polynomial to NOT be the commitment of the previous
        // share
        let (dkgs, public) = setup_reshare::<BCurve>(n, thr, 0, 0);
        let group = dkgs[0].info.prev_group.clone();
        let target_idx: usize = 0;
        let inv_public = |mut s: Vec<BundledShares<BCurve>>| {
            let nsecret = Poly::<Scalar>::new_from(thr - 1, &mut thread_rng());
            let npublic = nsecret.commit::<G1>();
            s[target_idx] = create_share_bundle(
                s[target_idx].dealer_idx,
                &nsecret,
                &npublic,
                &group,
                &mut thread_rng(),
            )
            .unwrap();
            s
        };
        let reshared = invalid_shares(
            thr,
            dkgs,
            inv_public,
            id_resp,
            |j| {
                assert_eq!(j.len(), 1);
                assert_eq!(j[0].dealer_idx, target_idx as u32);
                j
            },
            |outs| outs.into_iter().filter(|o| o.share.index != 0).collect(),
        )
        .unwrap();
        // test that it gives the same public key
        assert_eq!(public.public_key(), reshared.public_key());

        // SCENARIO 3
        // less than a threshold of old nodes is giving good shares
        let (dkgs, _) = setup_reshare::<BCurve>(n, thr, 0, 0);
        let group = dkgs[0].info.prev_group.clone();
        invalid_shares(
            thr,
            dkgs,
            |bundles| {
                bundles
                    .into_iter()
                    .map(|mut b| {
                        if b.dealer_idx < (n - thr) as u32 {
                            return b;
                        }
                        let msg = vec![1, 9, 6, 9];
                        b.shares[((b.dealer_idx + 1) as usize % group.len()) as usize].secret =
                            ecies::encrypt::<BCurve, _>(
                                &G1::rand(&mut thread_rng()),
                                &msg,
                                &mut thread_rng(),
                            );
                        b
                    })
                    .collect()
            },
            id_resp,
            // we skip too many justifications such that the protocol should
            // fail
            |bundles| bundles.into_iter().skip(thr - 1).collect(),
            |outs| outs.into_iter().filter(|o| o.share.index != 0).collect(),
        )
        .unwrap_err();
    }

    #[test]
    fn test_full_resharing() {
        // SCENARIO: reshare from a group to same group
        let n = 5;
        let thr = default_threshold(n);
        let (dkgs, public) = setup_reshare::<BCurve>(n, thr, 0, 0);
        let (_, reshared) = full_dkg(thr, dkgs);
        // test that it gives the same public key
        assert_eq!(public.public_key(), reshared.public_key());
    }

    #[test]
    fn test_resharing_added_members() {
        // SCENARIO: reshare with some new members
        let n = 5;
        let thr = default_threshold(n);
        let n2 = 8;
        let thr2 = 5;
        let (dkgs, public) = setup_reshare::<BCurve>(n, thr, n2, thr2);
        let (_, reshared) = full_dkg(thr2, dkgs);
        // test that it gives the same public key
        assert_eq!(public.public_key(), reshared.public_key());
    }

    #[test]
    fn test_resharing_added_members_invalid() {
        // SCENARIO: reshare with new members but give invalid shares
        let n = 5;
        let thr = default_threshold(n);
        let n2 = 8;
        let thr2 = 5;
        let (dkgs, public) = setup_reshare::<BCurve>(n, thr, n2, thr2);
        let reshared = invalid_shares(
            thr2,
            dkgs,
            |mut s| {
                s[0].shares[5].secret = ecies::encrypt(&G1::one(), &[1], &mut thread_rng());
                s[3].shares[6].secret = ecies::encrypt(&G1::one(), &[1], &mut thread_rng());
                s
            },
            id_resp,
            check2,
            id_out,
        )
        .unwrap();
        // test that it gives the same public key
        assert_eq!(public.public_key(), reshared.public_key());
    }
}
