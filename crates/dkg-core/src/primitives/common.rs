use crate::primitives::{
    group::Group,
    status::{Status, StatusMatrix},
    types::*,
    DKGError, DKGResult, ShareError,
};

use rand_core::RngCore;
use std::collections::HashMap;
use threshold_bls::{
    ecies,
    group::{Curve, Element},
    poly::{Idx, PrivatePoly, PublicPoly},
};

pub type ShareInfo<C> = HashMap<Idx, <C as Curve>::Scalar>;
pub type PublicInfo<C> = HashMap<Idx, PublicPoly<C>>;

pub fn decrypt_and_check_share<C: Curve>(
    private_key: &C::Scalar,
    own_idx: Idx,
    dealer_idx: Idx,
    public: &PublicPoly<C>,
    share: &EncryptedShare<C>,
) -> Result<C::Scalar, DKGError> {
    let buff = ecies::decrypt::<C>(private_key, &share.secret).map_err(|err| {
        println!("ERROR {:?}", err);
        ShareError::InvalidCiphertext(dealer_idx, err)
    })?;

    let clear_share: C::Scalar = bincode::deserialize(&buff)?;

    if !share_correct::<C>(own_idx, &clear_share, public) {
        println!("INCORRECT");
        return Err(ShareError::InvalidShare(dealer_idx).into());
    }

    Ok(clear_share)
}

/// set_statuses set the status of the given responses on the status matrix.
pub fn set_statuses<C: Curve>(
    holder_idx: Idx,
    dealers: &Group<C>,
    holders: &Group<C>,
    statuses: &mut StatusMatrix,
    responses: &[BundledResponses],
) {
    // makes sure the API doesn't take into account our own responses!
    let not_from_me = responses.iter().filter(|r| r.share_idx != holder_idx);
    let valid_idx = not_from_me.filter(|r| {
        let good_holder = holders.contains_index(r.share_idx);
        let good_dealers = !r
            .responses
            .iter()
            .any(|resp| !dealers.contains_index(resp.dealer_idx));
        good_dealers && good_holder
    });

    for bundle in valid_idx {
        let holder_index = bundle.share_idx;
        for response in bundle.responses.iter() {
            let dealer_index = response.dealer_idx;
            statuses.set(dealer_index, holder_index, response.status);
        }
    }
}

/// Checks if the commitment to the share corresponds to the public polynomial's
/// evaluated at the given point.
pub fn share_correct<C: Curve>(idx: Idx, share: &C::Scalar, public: &PublicPoly<C>) -> bool {
    let mut commit = C::Point::one();
    commit.mul(share);
    let pub_eval = public.eval(idx);
    pub_eval.value == commit
}

/// Creates the encrypted shares with the given secret polynomial to the given
/// group.
pub fn create_share_bundle<C: Curve, R: RngCore>(
    dealer_idx: Idx,
    secret: &PrivatePoly<C>,
    public: &PublicPoly<C>,
    group: &Group<C>,
    rng: &mut R,
) -> DKGResult<BundledShares<C>> {
    let shares = group
        .nodes
        .iter()
        .map(|n| {
            // evaluate the secret polynomial at the node's id
            let sec = secret.eval(n.id() as Idx);

            // serialize the evaluation
            let buff = bincode::serialize(&sec.value)?;

            // encrypt it
            let cipher = ecies::encrypt::<C, _>(n.key(), &buff, rng);

            // save the share
            Ok(EncryptedShare {
                share_idx: n.id(),
                secret: cipher,
            })
        })
        .collect::<Result<Vec<_>, DKGError>>()?;
    // Return the encrypted shares along with a commitment
    // to their secret polynomial.
    Ok(BundledShares {
        dealer_idx,
        shares,
        public: public.clone(),
    })
}

pub fn compute_bundle_response(
    my_idx: Idx,
    statuses: &StatusMatrix,
    publish_all: bool,
) -> Option<BundledResponses> {
    let responses = statuses
        .get_for_share(my_idx)
        .into_iter()
        .enumerate()
        .map(|(i, b)| Response {
            dealer_idx: i as Idx,
            status: Status::from(b),
        });

    let responses = if !publish_all {
        // only get the complaints
        responses
            .filter(|r| !r.status.is_success())
            .collect::<Vec<_>>()
    } else {
        responses.collect::<Vec<_>>()
    };

    if !responses.is_empty() {
        Some(BundledResponses {
            responses,
            share_idx: my_idx,
        })
    } else {
        None
    }
}

/// Processes the shares and returns the private share of the user and a public
/// polynomial, as well as the status matrix of the protocol.
///
/// Depending on which variant of the DKG protocol is used, the status
/// matrix responses which correspond to our index may be used in the
/// following way:
///
/// - All responses get broadcast: You assume that shares of other nodes are
/// not good unless you hear otherwise.  - Broadcast only responses which
/// are complaints: You assume that shares of other nodes are good unless
/// you hear otherwise.
pub fn process_shares_get_all<C: Curve>(
    dealers: &Group<C>,
    share_holders: &Group<C>,
    my_dealer_idx: Option<Idx>,
    my_idx: Idx,
    my_private: &C::Scalar,
    bundles: &[BundledShares<C>],
) -> DKGResult<(ShareInfo<C>, PublicInfo<C>, StatusMatrix)> {
    // there are "old_n" dealers and for each dealer, "new_n" share holders
    let mut statuses = StatusMatrix::new(dealers.len(), share_holders.len(), Status::Success);

    // set by default all the shares we could receive as complaint - that puts
    // us on the conservative side of only explicitely allowing correct shares.
    (0..dealers.len())
        .filter(|&dealer_idx| dealer_idx != my_idx as usize)
        .for_each(|dealer_idx| {
            statuses.set(dealer_idx as Idx, my_idx, Status::Complaint);
        });

    let mut publics = PublicInfo::<C>::new();
    let valid_shares = bundles
        .iter()
        // check the ones that are not from us (do not filter if there was no dealer idx specified)
        .filter(|b| my_dealer_idx.map(|idx| b.dealer_idx != idx).unwrap_or(true))
        //check the ones with a valid dealer index
        .filter(|b| dealers.contains_index(b.dealer_idx))
        // only consider public polynomial of the right form
        .filter(|b| b.public.degree() == share_holders.threshold - 1)
        // save them for later
        .inspect(|b| {
            publics.insert(b.dealer_idx, b.public.clone());
        })
        // get the share which corresponds to us
        .filter_map(|b| {
            // TODO: Return an error if there are multiple cases where the share
            // index matches ours.
            // `.find` stops at the first occurence only.
            b.shares
                .iter()
                .find(|s| s.share_idx == my_idx)
                .map(|share| (b, share))
        })
        // try to decrypt it (ignore invalid decryptions)
        .filter_map(|(bundle, encrypted_share)| {
            decrypt_and_check_share(
                my_private,
                my_idx,
                bundle.dealer_idx,
                &bundle.public,
                encrypted_share,
            )
            .map(|share| (bundle.dealer_idx, share))
            .ok()
        })
        .fold(ShareInfo::<C>::new(), |mut acc, (didx, share)| {
            println!(" -- got new share from {}", didx);
            statuses.set(didx, my_idx, Status::Success);
            acc.insert(didx, share);
            acc
        });

    Ok((valid_shares, publics, statuses))
}

pub fn get_justification<C: Curve>(
    dealer_idx: Idx,
    secret: &PrivatePoly<C>,
    public: &PublicPoly<C>,
    statuses: &StatusMatrix,
) -> Option<BundledJustification<C>> {
    // If there were any complaints against our deal, then we should re-evaluate our
    // secret polynomial at the indexes where the complaints were, and publish these
    // as justifications (i.e. indicating that we are still behaving correctly).
    if !statuses.all_true(dealer_idx) {
        let justifications = statuses
            .get_for_dealer(dealer_idx)
            .iter()
            .enumerate()
            .filter_map(|(i, success)| {
                if !success {
                    // reveal the share
                    let id = i as Idx;
                    Some(Justification {
                        share_idx: id,
                        share: secret.eval(id).value,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Some(BundledJustification {
            dealer_idx,
            justifications,
            public: public.clone(),
        })
    } else {
        None
    }
}

/// returns the correct shares destined to the given holder index
pub fn internal_process_justifications<C: Curve>(
    holder_idx: Idx,
    dealers: &Group<C>,
    statuses: &mut StatusMatrix,
    publics: &PublicInfo<C>,
    justifs: &[BundledJustification<C>],
) -> ShareInfo<C> {
    let mut valid_shares = ShareInfo::<C>::new();
    justifs
        .iter()
        .filter(|b| dealers.contains_index(b.dealer_idx))
        // get only the bundles for which we have a public polynomial for
        // i.e. only justif for polynomials that have been broadcasted in the
        // first phase
        .filter_map(|b| publics.get(&b.dealer_idx).map(|public| (b, public)))
        .for_each(|(bundle, public)| {
            bundle
                .justifications
                .iter()
                // ignore incorrect shares
                .filter(|justification| {
                    share_correct::<C>(justification.share_idx, &justification.share, public)
                })
                .for_each(|justification| {
                    // justification is valid, we mark it off from our matrix
                    statuses.set(bundle.dealer_idx, justification.share_idx, Status::Success);
                    if holder_idx == justification.share_idx {
                        valid_shares.insert(bundle.dealer_idx, justification.share.clone());
                    }
                })
        });
    valid_shares
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::primitives::phases::{Phase0, Phase1, Phase2, Phase3};
    use rand::thread_rng;
    use threshold_bls::poly::{Eval, Poly, PolyError};

    fn reconstruct<C: Curve>(
        thr: usize,
        shares: &[DKGOutput<C>],
    ) -> Result<PrivatePoly<C>, PolyError> {
        let evals: Vec<_> = shares
            .iter()
            .map(|o| Eval {
                value: o.share.private.clone(),
                index: o.share.index,
            })
            .collect();
        Poly::<C::Scalar>::full_recover(thr, evals)
    }

    pub fn setup_group<C: Curve>(n: usize, thr: usize) -> (Vec<C::Scalar>, Group<C>) {
        let privs = (0..n)
            .map(|_| C::Scalar::rand(&mut thread_rng()))
            .collect::<Vec<_>>();

        let pubs: Vec<C::Point> = privs
            .iter()
            .map(|private| {
                let mut public = C::Point::one();
                public.mul(private);
                public
            })
            .collect();
        let mut group = Group::from(pubs);
        group.threshold = thr;
        (privs, group)
    }

    pub fn invalid2<C: Curve>(mut s: Vec<BundledShares<C>>) -> Vec<BundledShares<C>> {
        // modify a share
        s[0].shares[1].secret = ecies::encrypt(&C::point(), &[1], &mut thread_rng());
        s[3].shares[4].secret = ecies::encrypt(&C::point(), &[1], &mut thread_rng());
        s
    }

    pub fn id_resp(r: Vec<BundledResponses>) -> Vec<BundledResponses> {
        r
    }

    pub fn check2<C: Curve>(j: Vec<BundledJustification<C>>) -> Vec<BundledJustification<C>> {
        // there should be exactly 2 complaints, one for each bad share where
        // decryption failed
        assert_eq!(j.len(), 2);
        j
    }

    pub fn id_out<C: Curve>(o: Vec<DKGOutput<C>>) -> Vec<DKGOutput<C>> {
        o
    }

    #[allow(clippy::needless_collect)]
    pub fn invalid_shares<C, P>(
        thr: usize,
        dkgs: Vec<P>,
        map_share: impl Fn(Vec<BundledShares<C>>) -> Vec<BundledShares<C>>,
        map_resp: impl Fn(Vec<BundledResponses>) -> Vec<BundledResponses>,
        map_just: impl Fn(Vec<BundledJustification<C>>) -> Vec<BundledJustification<C>>,
        map_out: impl Fn(Vec<DKGOutput<C>>) -> Vec<DKGOutput<C>>,
    ) -> DKGResult<PublicPoly<C>>
    where
        C: Curve,
        P: Phase0<C>,
    {
        let n = dkgs.len();
        let mut all_shares = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, shares) = dkg.encrypt_shares(&mut thread_rng()).unwrap();
                if let Some(sh) = shares {
                    all_shares.push(sh);
                }
                ndkg
            })
            .collect();

        let all_shares = map_share(all_shares);

        let mut response_bundles = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares, false).unwrap();
                if let Some(bundle) = bundle_o {
                    response_bundles.push(bundle);
                }
                ndkg
            })
            .collect();

        let response_bundles = map_resp(response_bundles);

        let mut justifications = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| match dkg.process_responses(&response_bundles) {
                Ok(_) => panic!("dkg shouldn't have finished OHE"),
                Err(next) => match next {
                    Ok((ndkg, justifs)) => {
                        if let Some(j) = justifs {
                            justifications.push(j);
                        }
                        ndkg
                    }
                    Err(e) => std::panic::panic_any(e),
                },
            })
            .collect();

        let justifications = map_just(justifications);

        // ...and the DKG finishes correctly as expected
        let outputs = dkgs
            .into_iter()
            .map(|dkg| dkg.process_justifications(&justifications))
            .collect::<Result<Vec<_>, DKGError>>()?;

        let outputs = map_out(outputs);

        let recovered_private = reconstruct(thr, &outputs).unwrap();
        let recovered_public = recovered_private.commit::<C::Point>();
        let recovered_key = recovered_public.public_key();
        for out in outputs.iter() {
            let public = &out.public;
            assert_eq!(public.public_key(), recovered_key);
        }
        Ok(recovered_public)
    }

    #[allow(clippy::needless_collect)]
    pub fn full_dkg<C, P>(nthr: usize, dkgs: Vec<P>) -> (Vec<DKGOutput<C>>, PublicPoly<C>)
    where
        C: Curve,
        P: Phase0<C>,
    {
        let n = dkgs.len();

        // Step 1. evaluate polynomial, encrypt shares and broadcast
        let mut all_shares = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, shares) = dkg.encrypt_shares(&mut thread_rng()).unwrap();
                if let Some(sh) = shares {
                    all_shares.push(sh);
                }
                ndkg
            })
            .collect();

        // Step 2. verify the received shares (there should be no complaints)
        let response_bundles = Vec::with_capacity(n);

        // Step 3. get the responses
        let outputs = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares, false).unwrap();
                assert!(
                    bundle_o.is_none(),
                    "full dkg should not have any complaints"
                );
                ndkg
            })
            .map(|dkg| dkg.process_responses(&response_bundles).expect("wholo"))
            .collect::<Vec<_>>();

        // Reconstruct the threshold private polynomial from all the outputs
        let recovered_private = reconstruct(nthr, &outputs).unwrap();
        // Get the threshold public key from the private polynomial
        let recovered_public = recovered_private.commit::<C::Point>();
        // let mut recovered_public = G1::one();
        // recovered_public.mul(&recovered_private);
        let recovered_key = recovered_public.public_key();

        // it matches with the outputs of each DKG participant, even though they
        // do not have access to the threshold private key
        for out in outputs.iter() {
            //println!("out.publickey(): {:?}", out.public.public_key());
            assert_eq!(out.public.public_key(), recovered_key);
        }
        (outputs, recovered_public)
    }
}
